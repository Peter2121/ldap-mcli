package ldap

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	//	"regexp"
	"strings"

	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/slice"
	"github.com/go-ldap/ldap/v3"
	"github.com/oleiade/reflections"
	"github.com/r3labs/diff/v3"
)

const (
	UserStatusActive   = "Active"
	UserStatusDisabled = "Disabled"
	UserStatusRevoked  = "Revoked"
	UserStatusDeleted  = "Deleted"

	userAlreadyExistsMsg   = "User with uid = '%s' already exists"
	userNotFoundMsg        = "User with %s = '%s' was not found"
	invalidStatusErrMsg    = "Invalid status '%s'. Valid status's are %v"
	invalidFilterKeyErrMsg = "Invalid filter key '%s'. Valid filter keys are %v"
	invalidPasswordErrMsg  = "Invalid password '%s'"
)

var (
	validStatusList = []string{
		UserStatusActive,
		UserStatusDisabled,
		UserStatusRevoked,
		UserStatusDeleted,
	}
)

type (
	// UsersManager describes an interface the needs to be implemented for performing operations on
	// all user accounts in LDAP.
	UsersManager interface {
		GetAll() ([]User, *errors.Error)
		GetByUid(uid string) (*User, *errors.Error)
		GetByEmail(email string) (*User, *errors.Error)
		Filter(key, value string) ([]User, *errors.Error)
		FilterByStatus(status string) ([]User, *errors.Error)
		Create(user User) *errors.Error
		ModifyUser(user, old_user User) *errors.Error
		DeleteByUid(uid string) *errors.Error
		DeleteByEmail(email string) *errors.Error
		Authenticate() *errors.Error
		SetNewPassword(uid, newPassword string) (string, *errors.Error)
	}

	// usersManager implements the UsersManager interface.
	usersManager struct {
		Client                *Client
		LdapUserAttributes    []string
		LdapUserAttributesMap map[string]string
	}

	// User represents the attributes of a user in LDAP
	User struct {
		Dn                   string   `json:"dn" diff:"dn,immutable" required:"false"`
		Uid                  string   `json:"uid" diff:"uid,immutable" ldap:"uid" required:"true"`
		Cn                   string   `json:"cn" diff:"cn" ldap:"cn" required:"true"`
		Sn                   string   `json:"sn" diff:"sn" ldap:"sn" required:"true"`
		DisplayName          string   `json:"displayName" diff:"displayName" ldap:"displayName" required:"false"`
		Mail                 string   `json:"mail" diff:"mail,immutable" ldap:"mail" required:"true"`
		UserPassword         string   `json:"userPassword,omitempty" diff:"userPassword" ldap:"userPassword" required:"true"`
		Status               string   `json:"accountStatus" diff:"accountStatus" ldap:"accountStatus" required:"true" default:"active"`
		DomainAdmin          string   `json:"domainGlobalAdmin,omitempty" diff:"domainGlobalAdmin" ldap:"domainGlobalAdmin" required:"false"`
		GivenName            string   `json:"givenName,omitempty" diff:"givenName" ldap:"givenName" required:"false"`
		HomeDirectory        string   `json:"homeDirectory,omitempty" diff:"homeDirectory,immutable" ldap:"homeDirectory" required:"false"`
		MailboxFormat        string   `json:"mailboxFormat,omitempty" diff:"mailboxFormat,immutable" ldap:"mailboxFormat" required:"false" default:"maildir"`
		MailMessageStore     string   `json:"mailMessageStore,omitempty" diff:"mailMessageStore,immutable" ldap:"mailMessageStore" required:"false"`
		MailQuota            string   `json:"mailQuota,omitempty" diff:"mailQuota" ldap:"mailQuota" required:"false" default:"1073741824"`
		StorageBaseDirectory string   `json:"storageBaseDirectory,omitempty" diff:"storageBaseDirectory,immutable" ldap:"storageBaseDirectory" required:"false" default:"/var/vmail"`
		EnabledServices      []string `json:"enabledService,omitempty" diff:"enabledService" ldap:"enabledService" required:"false"`
		MailAliases          []string `json:"shadowAddress,omitempty" diff:"shadowAddress" ldap:"shadowAddress" required:"false"`
	}
)

func NewUsersManager(ldap_lient *Client) *usersManager {
	var um usersManager
	um.Client = ldap_lient
	u := User{}
	um.LdapUserAttributesMap, _ = reflections.Tags(u, "ldap")
	for _, tag_value := range um.LdapUserAttributesMap {
		um.LdapUserAttributes = append(um.LdapUserAttributes, tag_value)
	}
	return &um
}

func (um *usersManager) GetNotFoundMessage(srchAttr, srchStr string) string {
	return fmt.Sprintf(userNotFoundMsg, srchAttr, srchStr)
}

// GetAll retrieves all the user entries from LDAP.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) GetAll() ([]User, *errors.Error) {
	sr := um.getUsersSearchRequest(userSearchFilter)
	result, err := um.Client.doLDAPSearch(sr)
	if err != nil {
		return nil, err
	}
	return um.parseSearchResult(result), nil
}

// GetByUid retrieves a single user's entry from LDAP.
// params:
//
//	uid = user identifier
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) GetByUid(uid string) (*User, *errors.Error) {
	if cErr := um.validateUid(uid); cErr != nil {
		return nil, cErr
	}
	sr := um.getUserSearchRequest(userIdAttr, uid)
	result, cErr := um.Client.doLDAPSearch(sr)
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, userIdAttr, uid))
		}
		return nil, cErr
	}
	ret := um.parseSearchResult(result)
	if len(ret) > 0 {
		return &(ret[0]), nil
	} else {
		return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, userIdAttr, uid))
	}
}

// GetByEmail retrieves a single user's entry from LDAP.
// params:
//
//	email = user mail address
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) GetByEmail(email string) (*User, *errors.Error) {
	if cErr := um.validateUid(email); cErr != nil {
		return nil, cErr
	}
	sr := um.getUserSearchRequest(MailAttr, email)
	result, cErr := um.Client.doLDAPSearch(sr)
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, MailAttr, email))
		}
		return nil, cErr
	}
	ret := um.parseSearchResult(result)
	if len(ret) > 0 {
		return &(ret[0]), nil
	} else {
		return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, MailAttr, email))
	}
}

// Filter retrieves a list of user entries from LDAP which is filtered based on the filter passed to the method
// as input. The filter is represented by a key and a value.
// params:
//
//	key 	= The key of the filter
//	value 	=  The value of the filter
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Filter(key, value string) ([]User, *errors.Error) {
	if cErr := um.validateFilter(key, value); cErr != nil {
		return nil, cErr
	}
	userSearchFilter := fmt.Sprintf(UserSearchFilter, key, value)
	sr := um.getUsersSearchRequest(userSearchFilter)
	result, err := um.Client.doLDAPSearch(sr)
	if err != nil {
		return nil, err
	}
	return um.parseSearchResult(result), nil
}

// FilterByStatus retrieves a list of user entries from LDAP which is filtered based on the status of the user entry.
// params:
//
//	status = the status of a user record
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) FilterByStatus(status string) ([]User, *errors.Error) {
	if cErr := um.validateStatus(status); cErr != nil {
		return nil, cErr
	}
	return um.Filter(statusAttr, status)
}

// Create a new user entry in LDAP.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Create(user User) *errors.Error {
	if cErr := um.validateUser(user); cErr != nil {
		return cErr
	}
	um.SetDefaults(&user)
	ar := um.getAddRequest(user)

	if cErr := um.Client.doLDAPAdd(ar); cErr != nil {
		if cErr.Status == http.StatusBadRequest {
			return errors.ConflictError(fmt.Sprintf(userAlreadyExistsMsg, user.Uid))
		} else {
			return cErr
		}
	}

	if _, cErr := um.modifyPassword(MailAttr, user.Mail, user.UserPassword, user.UserPassword); cErr != nil {
		return cErr
	}

	return nil
}

// DeleteByUid an existing user entry from LDAP.
// param:
//
//	uid = user identifier
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) DeleteByUid(uid string) *errors.Error {
	if cErr := um.validateUid(uid); cErr != nil {
		return cErr
	}
	dr, errreq := um.getDeleteRequest(userIdAttr, uid)
	if errreq != nil {
		return errreq
	}
	if dr == nil {
		return errors.InternalServerError("Cannot get LDAP delete request for uid")
	}
	if cErr := um.Client.doLDAPDelete(dr); cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, userIdAttr, uid))
		} else {
			return cErr
		}
	}
	return nil
}

// DeleteByEmail an existing user entry from LDAP.
// param:
//
//	uid = user identifier
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) DeleteByEmail(email string) *errors.Error {
	if cErr := um.validateUid(email); cErr != nil {
		return cErr
	}
	dr, errreq := um.getDeleteRequest(MailAttr, email)
	if errreq != nil {
		return errreq
	}
	if dr == nil {
		return errors.InternalServerError("Cannot get LDAP delete request for mail")
	}
	if cErr := um.Client.doLDAPDelete(dr); cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, MailAttr, email))
		} else {
			return cErr
		}
	}
	return nil
}

// Authenticate check if a user account can authenticate to LDAP.
// The bind credentials set using client.SetBindCredentials will be used to authenticating to LDAP.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Authenticate() *errors.Error {
	return um.Client.connect()
}

// SetNewPassword sets a new password for an existing user entry in LDAP.
// param:
//
//	uid 		= user identifier
//	newPassword = a new password to be set for the user
//
// If newPassword is empty then a new password will be generated for the user. The generated
// password will be updated for the user account and will be returned by the method.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) SetNewPassword(uid, newPassword string) (string, *errors.Error) {
	if newPassword == "" {
		result, cErr := um.modifyPassword(userIdAttr, uid, "", "")
		if cErr != nil {
			return "", cErr
		}
		return result.GeneratedPassword, nil
	} else {
		_, cErr := um.modifyPassword(userIdAttr, uid, "", newPassword)
		if cErr != nil {
			return "", cErr
		}
		return newPassword, nil
	}
}

// getDN returns the formatted LDAP user domain name or empty string
// if attr is not a principal attribute - LDAP search will be performed
func (um *usersManager) getDN(attr, uid, ou string) string {
	if attr == um.Client.UserDnAttribute {
		if len(ou) == 0 {
			return fmt.Sprintf("%s=%s,%s", attr, uid, um.Client.ConfigLdap.UserBaseDN)
		} else {
			return fmt.Sprintf("%s=%s,ou=%s,%s", attr, uid, ou, um.Client.ConfigLdap.UserBaseDN)
		}
	} else {
		sr := um.getUserSearchRequest(attr, uid)
		result, cErr := um.Client.doLDAPSearch(sr)
		if cErr != nil {
			return ""
		}
		if len(result.Entries) == 0 {
			return ""
		}
		user_entry := result.Entries[0]
		return user_entry.DN
	}
}

// getUsersSearchRequest returns a ldap search request to get a list of users.
// The list of users retrieved depends on the userSearchFilter.
func (um *usersManager) getUsersSearchRequest(userSearchFilter string) *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseDN:       um.Client.ConfigLdap.UserBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       userSearchFilter,
		Attributes:   um.LdapUserAttributes,
		Controls:     nil,
	}
}

// getUserSearchRequest returns a ldap search request to get a single user entry.
// TODO: use Filter to search using a given attribute and not DN exact
func (um *usersManager) getUserSearchRequest(srchAttr, srchStr string) *ldap.SearchRequest {
	srchFilter := fmt.Sprintf(UserSearchFilter, srchAttr, srchStr)
	return &ldap.SearchRequest{
		BaseDN:       um.Client.ConfigLdap.UserBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       srchFilter,
		Attributes:   um.LdapUserAttributes,
		Controls:     nil,
	}
}

// getAddRequest returns a ldap add request to add a new user entry or nil
// TODO: add OU support
func (um *usersManager) getAddRequest(user User) *ldap.AddRequest {
	var ar *ldap.AddRequest = nil
	if MailAttr == um.Client.UserDnAttribute {
		ar = ldap.NewAddRequest(um.getDN(MailAttr, user.Mail, ""), nil)
	} else {
		// TODO: correctly manage another principal attribute than MailAttr
		return ar
	}
	ar.Attribute(objectClassAttr, um.Client.ObjectClassesMailUser)
	ar.Attribute(userIdAttr, []string{user.Uid})
	ar.Attribute(CommonNameAttr, []string{user.Cn})
	ar.Attribute(familyNameAttr, []string{user.Sn})
	ar.Attribute(displayNameAttr, []string{user.DisplayName})
	ar.Attribute(MailAttr, []string{user.Mail})
	ar.Attribute(userPasswordAttr, []string{user.UserPassword})
	ar.Attribute(statusAttr, []string{user.Status})
	if len(user.EnabledServices) != 0 {
		ar.Attribute(enabledServiceAttr, user.EnabledServices)
	} else {
		ar.Attribute(enabledServiceAttr, um.Client.User.DefaultEnabledServices)
	}
	if len(user.MailAliases) != 0 {
		ar.Attribute(shadowAddressAttr, user.MailAliases)
	} else {
		ar.Attribute(shadowAddressAttr, []string{""})
	}
	if strings.ToUpper(user.DomainAdmin) == "YES" {
		ar.Attribute(domainAdminAttr, []string{"yes"})
	}
	ar.Attribute(givenNameAttr, []string{user.GivenName})
	ar.Attribute(mailboxFormatAttr, []string{user.MailboxFormat})
	ar.Attribute(homeDirectoryAttr, []string{user.HomeDirectory})
	ar.Attribute(mailQuotaAttr, []string{user.MailQuota})

	return ar
}

// Helper function to compose homeDirectoryAttr and mailMessageStoreAttr attributes data
func (um *usersManager) getNewUserHomeDir(user User) (string, string) {
	var current_timestamp string
	if len(user.Mail) < 3 {
		return "", ""
	}
	ind := strings.Index(user.Mail, "@")
	if ind < 1 {
		return "", ""
	}
	user_name := user.Mail[:ind]
	domain_name := user.Mail[ind+1:]
	user_folder := ""
	ts := time.Now()
	current_timestamp = fmt.Sprintf("%d.%02d.%02d.%02d.%02d.%02d", ts.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second())
	basedir := fmt.Sprintf("%s/%s/%s", um.Client.User.BaseDirectory, um.Client.User.DataFolder, domain_name)
	for i := 0; i < 3 && i < ind; i++ {
		subdir := user.Mail[i : i+1]
		if subdir == "@" { // Normally never happens
			break
		}
		user_folder = fmt.Sprintf("%s/%s", user_folder, subdir)
	}
	return fmt.Sprintf("%s%s/%s-%s/", basedir, user_folder, user_name, current_timestamp), fmt.Sprintf("%s/%s%s/", um.Client.User.DataFolder, domain_name, user_folder)
}

// getPasswordModifyRequest returns a ldap password modify request.
func (um *usersManager) getPasswordModifyRequest(attr, uid, oldPassword, newPassword string) *ldap.PasswordModifyRequest {
	return ldap.NewPasswordModifyRequest(
		um.getDN(attr, uid, ""),
		oldPassword,
		newPassword,
	)
}

// getDeleteRequest return a ldap delete request.
// TODO: add OU support
func (um *usersManager) getDeleteRequest(attr, uid string) (*ldap.DelRequest, *errors.Error) {
	dn := um.getDN(attr, uid, "")
	if len(dn) > 0 {
		return ldap.NewDelRequest(dn, nil), nil
	} else {
		return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, attr, uid))
	}
}

// parseSearchResult parses the result of the LDAP user search query.
func (um *usersManager) parseSearchResult(result *ldap.SearchResult) []User {
	var users []User
	for _, e := range result.Entries {
		user := User{
			Dn:                   e.DN,
			Uid:                  e.GetAttributeValue(userIdAttr),
			Cn:                   e.GetAttributeValue(CommonNameAttr),
			Sn:                   e.GetAttributeValue(familyNameAttr),
			DisplayName:          e.GetAttributeValue(displayNameAttr),
			Mail:                 e.GetAttributeValue(MailAttr),
			UserPassword:         e.GetAttributeValue(userPasswordAttr),
			Status:               e.GetAttributeValue(statusAttr),
			DomainAdmin:          e.GetAttributeValue(domainAdminAttr),
			GivenName:            e.GetAttributeValue(givenNameAttr),
			HomeDirectory:        e.GetAttributeValue(homeDirectoryAttr),
			MailboxFormat:        e.GetAttributeValue(mailboxFormatAttr),
			MailMessageStore:     e.GetAttributeValue(mailMessageStoreAttr),
			MailQuota:            e.GetAttributeValue(mailQuotaAttr),
			StorageBaseDirectory: e.GetAttributeValue(storageBaseDirectoryAttr),
			EnabledServices:      e.GetAttributeValues(enabledServiceAttr),
			MailAliases:          e.GetAttributeValues(shadowAddressAttr),
		}
		users = append(users, user)
	}
	if len(users) == 0 {
		return []User{}
	}
	return users
}

// modifyPassword processes the ldap password modify request.
func (um *usersManager) modifyPassword(attr, uid, oldPassword, newPassword string) (*ldap.PasswordModifyResult, *errors.Error) {
	pmr := um.getPasswordModifyRequest(attr, uid, oldPassword, newPassword)
	result, cErr := um.Client.doLDAPPasswordModify(pmr)
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, userIdAttr, uid))
		} else {
			return nil, cErr
		}
	}
	return result, nil
}

// TODO: Add ou
func (um *usersManager) GetModifyRequest(attr, uid string) *ldap.ModifyRequest {
	return ldap.NewModifyRequest(um.getDN(attr, uid, ""), nil)
}

func (um *usersManager) ModifyUser(user, old_user User) *errors.Error {
	if (len(user.EnabledServices) == 1) && (user.EnabledServices[0] == DEFAULT) {
		user.EnabledServices = append([]string{}, um.Client.User.DefaultEnabledServices...)
	}
	d, errcd := diff.NewDiffer(diff.SliceOrdering(false))
	if errcd != nil {
		return errors.InternalServerError(fmt.Sprintf("Cannot create differ for users: %v", errcd))
	}
	changelog, errdif := d.Diff(old_user, user)
	if errdif != nil {
		return errors.InternalServerError(fmt.Sprintf("Cannot differ users: %v", errdif))
	}
	if len(changelog) == 0 {
		return errors.BadRequestError("Users are identical")
	}

	services_to_add := []string{}
	services_to_remove := []string{}
	var unchanged_services = false
	if (len(user.EnabledServices) == 0) && (len(old_user.EnabledServices) > 0) {
		services_to_add = append(services_to_add, "")
	} else if (len(user.EnabledServices) == 1) && (user.EnabledServices[0] == UNCHANGED) {
		unchanged_services = true
	}

	aliases_to_add := []string{}
	aliases_to_remove := []string{}
	var unchanged_aliases = false
	if (len(user.MailAliases) == 0) && (len(old_user.MailAliases) > 0) {
		aliases_to_add = append(aliases_to_add, "")
	} else if (len(user.MailAliases) == 1) && (user.MailAliases[0] == UNCHANGED) {
		unchanged_aliases = true
	}

	attrs_to_replace := make(map[string]string)
	attrs_to_add := make(map[string]string)
	attrs_to_delete := make(map[string]string)

	for _, ch := range changelog {
		switch ch.Path[0] {
		case enabledServiceAttr:
			if !unchanged_services {
				switch ch.Type {
				case diff.CREATE:
					services_to_add = append(services_to_add, ch.To.(string))
				case diff.DELETE:
					services_to_remove = append(services_to_remove, ch.From.(string))
				case diff.UPDATE:
					services_to_remove = append(services_to_remove, ch.From.(string))
					services_to_add = append(services_to_add, ch.To.(string))
				}
			}
		case shadowAddressAttr:
			if !unchanged_aliases {
				switch ch.Type {
				case diff.CREATE:
					aliases_to_add = append(aliases_to_add, ch.To.(string))
				case diff.DELETE:
					aliases_to_remove = append(aliases_to_remove, ch.From.(string))
				case diff.UPDATE:
					aliases_to_remove = append(aliases_to_remove, ch.From.(string))
					aliases_to_add = append(aliases_to_add, ch.To.(string))
				}
			}
		case userPasswordAttr:
			password := ch.To.(string)
			if len(password) > 0 {
				if errpasswd := um.validatePassword(password); errpasswd != nil {
					return errpasswd
				} else {
					switch ch.Type {
					case diff.UPDATE:
						attrs_to_replace[userPasswordAttr] = password
					}
				}
			}
		case statusAttr:
			status := ch.To.(string)
			if (um.validateStatus(status) == nil) && (len(status) > 0) {
				switch ch.Type {
				case diff.UPDATE:
					attrs_to_replace[statusAttr] = status
				}
			}
		case domainAdminAttr:
			switch ch.Type {
			case diff.UPDATE:
				is_domain_admin := ch.To.(string)
				if strings.ToUpper(is_domain_admin) == "YES" {
					attrs_to_replace[domainAdminAttr] = "yes"
				}
			case diff.CREATE:
				is_domain_admin := ch.To.(string)
				if strings.ToUpper(is_domain_admin) == "YES" {
					attrs_to_add[domainAdminAttr] = "yes"
				}
			case diff.DELETE:
				attrs_to_delete[domainAdminAttr] = ch.From.(string)
			}
		case mailQuotaAttr:
			quota_str := ch.To.(string)
			if len(quota_str) > 0 {
				switch ch.Type {
				case diff.CREATE:
				case diff.UPDATE:
					quota_int, errconv := strconv.Atoi(quota_str)
					if (errconv == nil) && (quota_int > 0) {
						attrs_to_replace[mailQuotaAttr] = strconv.Itoa(quota_int)
					}
				}
			}
		default:
			if slice.EntryExists(um.LdapUserAttributes, ch.Path[0]) {
				switch ch.Type {
				case diff.CREATE:
					attrs_to_add[ch.Path[0]] = ch.To.(string)
				case diff.DELETE:
					attrs_to_delete[ch.Path[0]] = ch.From.(string)
				case diff.UPDATE:
					attrs_to_replace[ch.Path[0]] = ch.To.(string)
				}
			}
		}
	}

	if (len(services_to_add) == 0) && (len(services_to_remove) == 0) &&
		(len(aliases_to_add) == 0) && (len(aliases_to_remove) == 0) &&
		(len(attrs_to_add) == 0) && (len(attrs_to_delete) == 0) && (len(attrs_to_replace) == 0) {
		return errors.InternalServerError(fmt.Sprintf("Cannot parse differ changelog: %v", changelog))
	}

	req := um.GetModifyRequest(MailAttr, user.Mail)

	if len(services_to_add) > 0 {
		req.Add(enabledServiceAttr, services_to_add)
	}
	if len(services_to_remove) > 0 {
		req.Delete(enabledServiceAttr, services_to_remove)
	}

	if len(aliases_to_add) > 0 {
		req.Add(shadowAddressAttr, aliases_to_add)
	}
	if len(aliases_to_remove) > 0 {
		req.Delete(shadowAddressAttr, aliases_to_remove)
	}

	for attr, attr_value := range attrs_to_replace {
		req.Replace(attr, []string{attr_value})
	}

	for attr, attr_value := range attrs_to_add {
		req.Add(attr, []string{attr_value})
	}

	for attr, attr_value := range attrs_to_delete {
		req.Delete(attr, []string{attr_value})
	}

	if cErr := um.Client.doLDAPModify(req); cErr != nil {
		return cErr
	}

	return nil
}

// validateUid checks if the uid is set.
func (um *usersManager) validateUid(uid string) *errors.Error {
	if strings.TrimSpace(uid) == "" {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], []string{userIdAttr})
	}
	return nil
}

// Sets default values for some user attributes (used on user creation)
// TODO: take the values from config file
func (um *usersManager) SetDefaults(user *User) {
	if user.DisplayName == "" {
		user.DisplayName = user.Sn
	}
	if user.Uid == "" {
		user.Uid = strings.Split(user.Mail, "@")[0]
	}
	if user.Status == "" {
		user.Status = UserStatusActive
	}
	if len(user.EnabledServices) == 0 {
		user.EnabledServices = append([]string{}, um.Client.User.DefaultEnabledServices...)
	}
	if len(user.MailAliases) == 0 {
		user.MailAliases = []string{""}
	}
	if user.HomeDirectory == "" {
		user.HomeDirectory, user.MailMessageStore = um.getNewUserHomeDir(*user)
		user.StorageBaseDirectory = um.Client.User.BaseDirectory
	}
	if user.MailboxFormat == "" {
		user.MailboxFormat = um.Client.User.MailboxFormat
	}
	if user.MailQuota == "" {
		user.MailQuota = strconv.Itoa(um.Client.User.DefaultUserQuota)
	}
}

// validateUser checks if all the required attributes of a User are set for creating a new user.
// TODO: use reflection and tags
func (um *usersManager) validateUser(user User) *errors.Error {

	var missingParams []string

	if strings.TrimSpace(user.Cn) == "" {
		missingParams = append(missingParams, CommonNameAttr)
	}
	if strings.TrimSpace(user.Sn) == "" {
		missingParams = append(missingParams, familyNameAttr)
	}
	if strings.TrimSpace(user.Mail) == "" {
		missingParams = append(missingParams, MailAttr)
	}
	if strings.TrimSpace(user.UserPassword) == "" {
		missingParams = append(missingParams, userPasswordAttr)
	}
	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	if cErr := um.validateStatus(user.Status); cErr != nil {
		return cErr
	}
	return nil
}

// validateFilter checks if the filter key and value is set.
func (um *usersManager) validateFilter(key, value string) *errors.Error {
	var missingParams []string
	if strings.TrimSpace(key) == "" {
		missingParams = append(missingParams, "key")
	}
	if strings.TrimSpace(value) == "" {
		missingParams = append(missingParams, "value")
	}
	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	if !slice.EntryExists(um.LdapUserAttributes, key) {
		return errors.BadRequestError(fmt.Sprintf(invalidFilterKeyErrMsg, key, um.LdapUserAttributes))
	}
	return nil
}

// validateStatus checks if the status attribute value is valid.
func (um *usersManager) validateStatus(status string) *errors.Error {
	if status == "" { // Will be set to default
		return nil
	}
	if !slice.EntryExists(validStatusList, status) {
		return errors.BadRequestError(fmt.Sprintf(invalidStatusErrMsg, status, validStatusList))
	}
	return nil
}

// TODO: add check of complexity, take minimal length from config
func (um *usersManager) validatePassword(password string) *errors.Error {
	if len(password) < 6 {
		return errors.BadRequestError(fmt.Sprintf(invalidPasswordErrMsg, password))
	}
	return nil
}
