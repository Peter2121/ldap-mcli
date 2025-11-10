package ldap

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/atselvan/go-utils/utils/errors"
	"github.com/go-ldap/ldap/v3"
	"github.com/oleiade/reflections"
	"github.com/r3labs/diff/v3"
)

const (
	GRP_TYPE_MAIL string = "Mail"
)

var defaultGroupMailEnabledServices = []string{
	"deliver",
	"mail",
	"displayedInGlobalAddressBook",
}

type (
	// groupsMailManager implements groupsMailManager.
	groupsMailManager struct {
		Client              *Client
		LdapGroupAttributes []string
	}

	// GroupMail represents an LDAP distribution group (mail list).
	GroupMail struct {
		Type            string   `json:"type" diff:"type,immutable" required:"true"`
		Dn              string   `json:"dn" diff:"dn,immutable" required:"false"`
		Cn              string   `json:"cn" diff:"cn,immutable" ldap:"cn" required:"true"`
		Status          string   `json:"accountStatus" diff:"accountStatus" ldap:"accountStatus" required:"true" default:"active"`
		Mail            string   `json:"mail" diff:"mail" ldap:"mail" required:"true"`
		EnabledServices []string `json:"enabledService,omitempty" diff:"enabledService" ldap:"enabledService" required:"false"`
		Members         []string `json:"member,omitempty" diff:"member" ldap:"member" required:"false"`
		MailAliases     []string `json:"shadowAddress,omitempty" diff:"shadowAddress" ldap:"shadowAddress" required:"false"`
	}
)

func NewGroupMailManager(ldap_lient *Client) *groupsMailManager {
	var gm groupsMailManager
	gm.Client = ldap_lient
	gm.LdapGroupAttributes = []string{}
	g := GroupMail{}
	ldap_tags, _ := reflections.Tags(g, "ldap")
	for _, tag_value := range ldap_tags {
		gm.LdapGroupAttributes = append(gm.LdapGroupAttributes, tag_value)
	}
	return &gm
}

var defaultObjectClassesGroupMail = []string{
	"mailList",
	"top",
}

func (g GroupMail) GetMembers() []string {
	return g.Members
}

func (gm *groupsMailManager) GetType() string {
	return GRP_TYPE_MAIL
}

func (gm *groupsMailManager) GetDefaultClasses() []string {
	return defaultObjectClassesGroupMail
}

func (gm *groupsMailManager) GetClient() *Client {
	return gm.Client
}

func (gm *groupsMailManager) GetAll() ([]GroupMail, *errors.Error) {
	return GetAll(&gm)
}

// Get retrieves a list of group entries from LDAP.
// The list of groups depends on the input value of cn.
// params:
//
//	cn = common name of the group
//
// The method returns an error:
//   - if any validation fails
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsMailManager) Get(cn, _ string) ([]GroupMail, *errors.Error) {
	req := gm.GetSearchRequest(cn, "", groupMailSearchFilter)
	result, cErr := gm.Client.doLDAPSearch(req)
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(groupNotFoundMsg, "cn", cn, ""))
		}
		return nil, cErr
	}
	return gm.ParseSearchResult(result), nil
}

func (gm *groupsMailManager) GetOne(attr, aval, ou string) (*GroupMail, *errors.Error) {
	// ou will be ignored for GroupMail car mailList objectClass does not have this attribute
	search_request_str := fmt.Sprintf(MailGroupsSearchFilter, attr, aval)
	ret, err := gm.GetFilteredGroups(search_request_str)
	if err == nil && len(ret) > 0 {
		return &(ret[0]), nil
	} else {
		return nil, errors.NotFoundError(fmt.Sprintf(groupNotFoundMsg, attr, aval, ou))
	}
}

func (gm *groupsMailManager) GetFilteredGroups(searchFilter string) ([]GroupMail, *errors.Error) {
	return GetFilteredGroups(&gm, searchFilter)
}

// Create adds a new group entry in LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit under which the group should be created
//	memberIds: a list of memberIds to be added as a unique member in the group
//
// If NO memberIds are provided then a default unique member NO_SUCH_USER will be added to the group during creation.
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group already exists
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsMailManager) Create(cn, ou string, memberIds []string) *errors.Error {
	return Create(&gm, cn, ou, memberIds)
}

func (gm *groupsMailManager) CreateGroup(group GroupMail) *errors.Error {
	if err := CreateGroup(&gm, group); err != nil {
		if err.Status == http.StatusBadRequest {
			return errors.ConflictError(fmt.Sprintf(groupAlreadyExistsMsg, group.Cn, ""))
		} else {
			return err
		}
	}
	return nil
}

func (gm *groupsMailManager) SetDefaults(group *GroupMail) {
	if group.Status == "" {
		group.Status = GroupStatusActive
	}
	if len(group.EnabledServices) == 0 {
		group.EnabledServices = append([]string{}, defaultGroupMailEnabledServices...)
	}
	if len(group.MailAliases) == 0 {
		group.MailAliases = []string{""}
	}
	if len(group.Members) == 0 {
		group.Members = []string{""}
	}
}

func (gm *groupsMailManager) Delete(cn, _ string) *errors.Error {
	return Delete(&gm, cn, "")
}

// AddMembers add uniqueMember(s) to an existing group entry in LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit under which the group exists
//	memberIds: a list of memberIds to be added as a unique member in the group
//
// If NO memberIds are provided then there will be no change.
// If there are more than one valid member in the group then the default unique member NO_SUCH_USER will be
// removed from the group during the update.
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsMailManager) AddMembers(cn, ou string, memberIds []string) *errors.Error {
	return AddMembers(&gm, cn, ou, memberIds)
	/*
		var uniqueMembers []string
		if err := gm.ValidateGroup(cn, ou); err != nil {
			return err
		}
		result, cErr := gm.Get(cn, ou)
		if cErr != nil {
			return cErr
		}
		group := result[0]
		mr := gm.GetModifyRequest(cn, ou)
		for _, memberId := range memberIds {
			uniqueMember := gm.GetUniqueMemberDn(strings.ToUpper(memberId))
			if !slice.EntryExists(group.Members, uniqueMember) {
				logger.Info(fmt.Sprintf(uniqueMemberWillBeAddedToGroupMsg, uniqueMember, gm.GetDN(cn, ou)))
				uniqueMembers = append(uniqueMembers, uniqueMember)
			}
		}
		if len(uniqueMembers) > 0 {
			mr.Add(uniqueMemberAttr, uniqueMembers)
		}
		if len(group.Members)+len(uniqueMembers) >= 2 {
			uniqueMember := gm.GetUniqueMemberDn(noSuchUserGroupMemberCn)
			mr.Delete(uniqueMemberAttr, []string{uniqueMember})
		}
		if cErr := gm.Client.doLDAPModify(mr); cErr != nil {
			return cErr
		}
		return nil
	*/
}

// RemoveMembers removes existing uniqueMember(s) from an existing group entry in LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit under which the group exists
//	memberIds: a list of memberIds to be added as a unique member in the group
//
// If NO memberIds are provided then there will be no change.
// If there are no more valid member in the group, the default unique member NO_SUCH_USER will be
// added to the group during the update.
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsMailManager) RemoveMembers(cn, ou string, memberIds []string) *errors.Error {
	return RemoveMembers(&gm, cn, ou, memberIds)
	/*
		var uniqueMembers []string
		if err := gm.ValidateGroup(cn, ou); err != nil {
			return err
		}
		result, cErr := gm.Get(cn, ou)
		if cErr != nil {
			return cErr
		}
		group := result[0]
		mr := gm.GetModifyRequest(cn, ou)
		for _, memberId := range memberIds {
			uniqueMember := gm.GetUniqueMemberDn(strings.ToUpper(memberId))
			if slice.EntryExists(group.Members, uniqueMember) {
				if memberId != noSuchUserGroupMemberCn {
					logger.Info(fmt.Sprintf(uniqueMemberWillBeRemovedFromGroupMsg, uniqueMember, gm.GetDN(cn, ou)))
				}
				uniqueMembers = append(uniqueMembers, uniqueMember)
			}
		}
		if len(uniqueMembers) > 0 {
			mr.Delete(uniqueMemberAttr, uniqueMembers)
		}
		if len(group.Members)-len(uniqueMembers) == 0 {
			uniqueMember := gm.GetUniqueMemberDn(strings.ToUpper(noSuchUserGroupMemberCn))
			mr.Add(uniqueMemberAttr, []string{uniqueMember})
		}
		if cErr := gm.Client.doLDAPModify(mr); cErr != nil {
			return cErr
		}
		return nil
	*/
}

// getDN returns the formatted domain name of a ldap group
func (gm *groupsMailManager) GetDN(cn, _ string) string {
	// GroupMail does not support ou as mailList objectClass does not provide such attribute
	if cn != "" {
		return fmt.Sprintf("%s=%s,%s", CommonNameAttr, cn, gm.Client.Config.GroupBaseDN)
	} else {
		return gm.Client.Config.GroupBaseDN
	}
}

// getUniqueMemberDn returns the formatted unique member domain name
func (gm *groupsMailManager) GetUniqueMemberDn(memberId string) string {
	return fmt.Sprintf("%s=%s,%s", userIdAttr, memberId, gm.Client.Config.UserBaseDN)
}

// GetSearchRequest returns a ldap search request
func (gm *groupsMailManager) GetSearchRequest(cn, ou, groupSearchFilter string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		gm.GetDN(cn, ou),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		groupSearchFilter,
		[]string{
			CommonNameAttr,
			statusAttr,
			MailAttr,
			enabledServiceAttr,
			uniqueMemberAttr,
		},
		nil,
	)
}

func (gm *groupsMailManager) GetAddRequest(group GroupMail) *ldap.AddRequest {
	dn := gm.GetDN(group.Cn, "")
	ar := ldap.NewAddRequest(dn, nil)
	ar.Attribute(objectClassAttr, defaultObjectClassesGroupMail)
	ar.Attribute(CommonNameAttr, []string{group.Cn})
	ar.Attribute(statusAttr, []string{group.Status})
	ar.Attribute(MailAttr, []string{group.Mail})
	ar.Attribute(enabledServiceAttr, group.EnabledServices)
	ar.Attribute(uniqueMemberAttr, group.Members)
	ar.Attribute(shadowAddressAttr, group.MailAliases)
	return ar
}

func (gm *groupsMailManager) GetModifyRequest(cn, ou string) *ldap.ModifyRequest {
	return ldap.NewModifyRequest(gm.GetDN(cn, ou), nil)
}

func (gm *groupsMailManager) GetDeleteRequest(cn, ou string) *ldap.DelRequest {
	return ldap.NewDelRequest(gm.GetDN(cn, ou), nil)
}

// ParseSearchResult parses the ldap search result and retrieves the group entries.
func (gm *groupsMailManager) ParseSearchResult(result *ldap.SearchResult) []GroupMail {
	var groups []GroupMail
	for _, entry := range result.Entries {
		group := GroupMail{
			Type:            gm.GetType(),
			Dn:              entry.DN,
			Cn:              entry.GetAttributeValue(CommonNameAttr),
			Status:          entry.GetAttributeValue(statusAttr),
			Mail:            entry.GetAttributeValue(MailAttr),
			EnabledServices: entry.GetAttributeValues(enabledServiceAttr),
			Members:         entry.GetAttributeValues(uniqueMemberAttr),
			MailAliases:     entry.GetAttributeValues(shadowAddressAttr),
		}
		groups = append(groups, group)
	}
	return groups
}

func (gm *groupsMailManager) ModifyGroup(group, old_group GroupMail) *errors.Error {
	errv := gm.ValidateGroup(group)
	if errv != nil {
		return errv
	}
	if (len(group.EnabledServices) == 1) && (group.EnabledServices[0] == DEFAULT) {
		group.EnabledServices = append([]string{}, defaultGroupMailEnabledServices...)
	}
	d, errcd := diff.NewDiffer(diff.SliceOrdering(false))
	if errcd != nil {
		return errors.InternalServerError(fmt.Sprintf("Cannot create differ for mail groups: %v", errcd))
	}
	changelog, errdif := d.Diff(old_group, group)
	if errdif != nil {
		return errors.InternalServerError(fmt.Sprintf("Cannot differ mail groups: %v", errdif))
	}
	if len(changelog) == 0 {
		return errors.BadRequestError("Groups are identical")
	}
	members_to_add := []string{}
	members_to_remove := []string{}
	var unchanged_members = false
	if (len(group.Members) == 0) && (len(old_group.Members) > 0) {
		members_to_add = append(members_to_add, "")
	} else if (len(group.Members) == 1) && (group.Members[0] == UNCHANGED) {
		unchanged_members = true
	}

	services_to_add := []string{}
	services_to_remove := []string{}
	var unchanged_services = false
	if (len(group.EnabledServices) == 0) && (len(old_group.EnabledServices) > 0) {
		services_to_add = append(services_to_add, "")
	} else if (len(group.EnabledServices) == 1) && (group.EnabledServices[0] == UNCHANGED) {
		unchanged_services = true
	}

	aliases_to_add := []string{}
	aliases_to_remove := []string{}
	var unchanged_aliases = false
	if (len(group.MailAliases) == 0) && (len(old_group.MailAliases) > 0) {
		aliases_to_add = append(aliases_to_add, "")
	} else if (len(group.MailAliases) == 1) && (group.MailAliases[0] == UNCHANGED) {
		unchanged_aliases = true
	}
	var new_status string = ""
	var new_mail string = ""
	for _, ch := range changelog {
		switch ch.Path[0] {
		case statusAttr:
			status := ch.To.(string)
			if validateGroupStatus(status) {
				switch ch.Type {
				case diff.UPDATE:
					new_status = status
				}
			}
		case MailAttr:
			switch ch.Type {
			case diff.UPDATE:
				new_mail = ch.To.(string)
			}
		case uniqueMemberAttr:
			if !unchanged_members {
				switch ch.Type {
				case diff.CREATE:
					members_to_add = append(members_to_add, ch.To.(string))
				case diff.DELETE:
					members_to_remove = append(members_to_remove, ch.From.(string))
				case diff.UPDATE:
					members_to_remove = append(members_to_remove, ch.From.(string))
					members_to_add = append(members_to_add, ch.To.(string))
				}
			}
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
		}
	}
	if (len(members_to_add) == 0) && (len(members_to_remove) == 0) &&
		(len(services_to_add) == 0) && (len(services_to_remove) == 0) &&
		(len(aliases_to_add) == 0) && (len(aliases_to_remove) == 0) &&
		(len(new_status) == 0) && (len(new_mail) == 0) {
		return errors.InternalServerError(fmt.Sprintf("Cannot parse differ changelog: %v", changelog))
	}
	req := gm.GetModifyRequest(group.Cn, "")

	if len(members_to_add) > 0 {
		req.Add(uniqueMemberAttr, members_to_add)
	}
	if len(members_to_remove) > 0 {
		req.Delete(uniqueMemberAttr, members_to_remove)
	}

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

	if len(new_status) > 0 {
		req.Replace(statusAttr, []string{new_status})
	}

	if len(new_mail) > 0 {
		req.Replace(MailAttr, []string{new_mail})
	}

	if cErr := gm.Client.doLDAPModify(req); cErr != nil {
		return cErr
	}
	return nil
}

// validateGroup checks if required information is provided for a ldap group
func (gm *groupsMailManager) ValidateGroup(group GroupMail) *errors.Error {
	var missingParams []string

	if strings.TrimSpace(group.Cn) == "" {
		missingParams = append(missingParams, CommonNameAttr)
	}
	if strings.TrimSpace(group.Mail) == "" {
		missingParams = append(missingParams, MailAttr)
	}

	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	return nil
}
