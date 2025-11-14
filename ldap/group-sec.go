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
	GRP_TYPE_SEC string = "Security"
)

type (
	// groupsSecManager implements GroupsManager.
	groupsSecManager struct {
		Client              *Client
		LdapGroupAttributes []string
	}

	// GroupSec represents an LDAP security group.
	GroupSec struct {
		Type    string   `json:"type" diff:"type,immutable" required:"true"`
		Dn      string   `json:"dn" diff:"dn,immutable" required:"false"`
		Cn      string   `json:"cn" diff:"cn,immutable" ldap:"cn" required:"true"`
		Ou      string   `json:"ou" diff:"ou,immutable" ldap:"ou" required:"false"`
		Members []string `json:"member,omitempty" diff:"member" ldap:"member" required:"false"`
	}
)

func NewGroupSecManager(ldap_lient *Client) *groupsSecManager {
	var gm groupsSecManager
	gm.Client = ldap_lient
	gm.LdapGroupAttributes = []string{}
	g := GroupSec{}
	ldap_tags, _ := reflections.Tags(g, "ldap")
	for _, tag_value := range ldap_tags {
		gm.LdapGroupAttributes = append(gm.LdapGroupAttributes, tag_value)
	}
	return &gm
}

var defaultObjectClassesGroupSec = []string{
	"groupOfNames",
	"top",
}

// Some getters

func (g GroupSec) GetMembers() []string {
	return g.Members
}

func (gm *groupsSecManager) GetType() string {
	return GRP_TYPE_SEC
}

func (gm *groupsSecManager) GetDefaultClasses() []string {
	return defaultObjectClassesGroupSec
}

func (gm *groupsSecManager) GetClient() *Client {
	return gm.Client
}

func (gm *groupsSecManager) GetAll() ([]GroupSec, *errors.Error) {
	return GetAll(&gm)
}

// Get retrieves a list of group entries from LDAP.
// The list of groups depends on the input values of cn and ou.
// params:
//
//	cn = common name of the group
//	ou = organization unit within which the group is contained
//
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsSecManager) Get(cn, ou string) ([]GroupSec, *errors.Error) {
	/* TODO: Validate ou!!!
	if ou != "" {
		if cErr := gm.validateGroupOu(ou); cErr != nil {
			return nil, cErr
		}
	}
	*/
	req := gm.GetSearchRequest(cn, ou, groupSecSearchFilter)
	result, cErr := gm.Client.doLDAPSearch(req)
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(groupNotFoundMsg, "cn", cn, ou))
		}
		return nil, cErr
	}
	return gm.ParseSearchResult(result), nil
}

func (gm *groupsSecManager) GetOne(attr, aval, ou string) (*GroupSec, *errors.Error) {
	/* TODO: Validate ou!!!
	/*
		if ou != "" {
			if cErr := gm.validateGroupOu(ou); cErr != nil {
				return nil, cErr
			}
		}
	*/
	var search_request_str string
	if ou != "" {
		search_request_str = fmt.Sprintf(SecGroupsOuSearchFilter, attr, aval, ou)
	} else {
		search_request_str = fmt.Sprintf(SecGroupsSearchFilter, attr, aval)
	}
	ret, err := gm.GetFilteredGroups(search_request_str)
	if err == nil && len(ret) > 0 {
		return &(ret[0]), nil
	} else {
		return nil, errors.NotFoundError(fmt.Sprintf(groupNotFoundMsg, attr, aval, ou))
	}
}

func (gm *groupsSecManager) GetFilteredGroups(searchFilter string) ([]GroupSec, *errors.Error) {
	return GetFilteredGroups(&gm, searchFilter)
}

func (gm *groupsSecManager) Create(cn, ou string, memberIds []string) *errors.Error {
	return Create(&gm, cn, ou, memberIds)
}

func (gm *groupsSecManager) CreateGroup(group GroupSec) *errors.Error {
	if err := CreateGroup(&gm, group); err != nil {
		if err.Status == http.StatusBadRequest {
			return errors.ConflictError(fmt.Sprintf(groupAlreadyExistsMsg, group.Cn, ""))
		} else {
			return err
		}
	}
	return nil
}

func (gm *groupsSecManager) SetDefaults(group *GroupSec) {
	if len(group.Members) == 0 {
		group.Members = []string{""}
	}
}

func (gm *groupsSecManager) Delete(cn, ou string) *errors.Error {
	return Delete(&gm, cn, ou)
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
func (gm *groupsSecManager) AddMembers(cn, ou string, memberIds []string) *errors.Error {
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
func (gm *groupsSecManager) RemoveMembers(cn, ou string, memberIds []string) *errors.Error {
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
		return
	*/
}

// getDN returns the formatted domain name of a ldap group
func (gm *groupsSecManager) GetDN(cn, ou string) string {
	if cn != "" && ou != "" {
		return fmt.Sprintf("%s=%s,%s=%s,%s", CommonNameAttr, cn, OrganizationalUnitAttr, ou,
			gm.Client.ConfigLdap.GroupBaseDN)
	} else if cn != "" {
		return fmt.Sprintf("%s=%s,%s", CommonNameAttr, cn, gm.Client.ConfigLdap.GroupBaseDN)
	} else if ou != "" {
		return fmt.Sprintf("%s=%s,%s", OrganizationalUnitAttr, ou, gm.Client.ConfigLdap.GroupBaseDN)
	} else {
		return gm.Client.ConfigLdap.GroupBaseDN
	}
}

// getUniqueMemberDn returns the formatted unique member domain name
func (gm *groupsSecManager) GetUniqueMemberDn(memberId string) string {
	return fmt.Sprintf("%s=%s,%s", userIdAttr, memberId, gm.Client.ConfigLdap.UserBaseDN)
}

// GetSearchRequest returns a ldap search request
func (gm *groupsSecManager) GetSearchRequest(cn, ou, groupSearchFilter string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		gm.GetDN(cn, ou),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		groupSearchFilter,
		gm.LdapGroupAttributes,
		nil,
	)
}

func (gm *groupsSecManager) GetAddRequest(group GroupSec) *ldap.AddRequest {
	dn := gm.GetDN(group.Cn, group.Ou)
	ar := ldap.NewAddRequest(dn, nil)
	ar.Attribute(objectClassAttr, defaultObjectClassesGroupSec)
	ar.Attribute(CommonNameAttr, []string{group.Cn})
	ar.Attribute(uniqueMemberAttr, group.Members)
	return ar
}

func (gm *groupsSecManager) GetModifyRequest(cn, ou string) *ldap.ModifyRequest {
	return ldap.NewModifyRequest(gm.GetDN(cn, ou), nil)
}

func (gm *groupsSecManager) GetDeleteRequest(cn, ou string) *ldap.DelRequest {
	return ldap.NewDelRequest(gm.GetDN(cn, ou), nil)
}

// ParseSearchResult parses the ldap search result and retrieves the group entries.
func (gm *groupsSecManager) ParseSearchResult(result *ldap.SearchResult) []GroupSec {
	var groups []GroupSec
	for _, entry := range result.Entries {
		group := GroupSec{
			Type:    gm.GetType(),
			Dn:      entry.DN,
			Cn:      entry.GetAttributeValue(CommonNameAttr),
			Members: entry.GetAttributeValues(uniqueMemberAttr),
		}
		groups = append(groups, group)
	}
	return groups
}

func (gm *groupsSecManager) ModifyGroup(group, old_group GroupSec) *errors.Error {
	errv := gm.ValidateGroup(group)
	if errv != nil {
		return errv
	}
	d, errcd := diff.NewDiffer(diff.SliceOrdering(false))
	if errcd != nil {
		return errors.InternalServerError(fmt.Sprintf("Cannot create differ for security groups: %v", errcd))
	}
	changelog, errdif := d.Diff(old_group, group)
	if errdif != nil {
		return errors.InternalServerError(fmt.Sprintf("Cannot differ security groups: %v", errdif))
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
	for _, ch := range changelog {
		switch ch.Path[0] {
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
		}
	}
	if (len(members_to_add) == 0) && (len(members_to_remove) == 0) {
		return errors.InternalServerError(fmt.Sprintf("Cannot parse differ changelog: %v", changelog))
	}
	req := gm.GetModifyRequest(group.Cn, group.Ou)
	if len(members_to_add) > 0 {
		req.Add(uniqueMemberAttr, members_to_add)
	}
	if len(members_to_remove) > 0 {
		req.Delete(uniqueMemberAttr, members_to_remove)
	}
	if cErr := gm.Client.doLDAPModify(req); cErr != nil {
		return cErr
	}
	return nil
}

// validateGroup checks if required information is provided for a ldap group
//
//	func (gm *groupsSecManager) ValidateGroup(cn, _ string) *errors.Error {
//		return validateGroup(cn)
//	}
func (gm *groupsSecManager) ValidateGroup(group GroupSec) *errors.Error {
	var missingParams []string

	if strings.TrimSpace(group.Cn) == "" {
		missingParams = append(missingParams, CommonNameAttr)
	}

	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	return nil
}

/*
func (gm *groupsSecManager) validateGroup(cn, _ string) *errors.Error {
	var missingParams []string

	if strings.TrimSpace(cn) == "" {
		missingParams = append(missingParams, CommonNameAttr)
	}
	//	if strings.TrimSpace(ou) == "" {
	//		missingParams = append(missingParams, OrganizationalUnitAttr)
	//	}
	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	//if err := gm.validateGroupOu(ou); err != nil {
	//	return err
	//}
	return nil
}
*/

// validateGroupOu checks if the ldap organizational unit is valid
/*
func (gm *groupsSecManager) validateGroupOu(ou string) *errors.Error {
	organizationalUnits, cErr := gm.Client.OrganizationalUnits.GetAll()
	if cErr != nil {
		return cErr
	}
	if !slice.EntryExists(organizationalUnits, ou) {
		return errors.BadRequestError(fmt.Sprintf(invalidOrganizationalUnitErrMsg, ou, organizationalUnits))
	}
	return nil
}
*/
