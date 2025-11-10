package ldap

import (
	"github.com/atselvan/go-utils/utils/errors"
	"github.com/go-ldap/ldap/v3"
)

const (
	GroupStatusActive       = "Active"
	GroupStatusDisabled     = "Disabled"
	noSuchUserGroupMemberCn = "NO_SUCH_USER"
	groupAlreadyExistsMsg   = "Group with cn = '%s' and ou = '%s' already exists"
	groupNotFoundMsg        = "Group with %s = '%s' and ou = '%s' was not found"
	//invalidOrganizationalUnitErrMsg       = "Invalid organizational unit '%s'. Valid values are %v"
	uniqueMemberWillBeAddedToGroupMsg            = "UniqueMember '%s' will be added to the group '%s'"
	uniqueMemberWillBeRemovedFromGroupMsg        = "UniqueMember '%s' will be removed from the group '%s'"
	DEFAULT                               string = "Default"
	UNCHANGED                             string = "Unchanged"
)

type BaseGroup struct {
	Type  string         `json:"type"`
	Dn    string         `json:"dn"`
	Cn    string         `json:"cn"`
	Other map[string]any `json:"-"`
}

var GROUP_TYPES []string = []string{"Mail", "Security"}

type (
	// GroupsManager describes the interface that needs to be implemented for performing operations on LDAP groups.
	GroupsManager[T any] interface {
		GetType() string
		GetDefaultClasses() []string
		GetClient() *Client
		GetAll() ([]T, *errors.Error)
		Get(cn, ou string) ([]T, *errors.Error)
		GetOne(attr, aval, ou string) (*T, *errors.Error)
		GetFilteredGroups(searchFilter string) ([]T, *errors.Error)
		Create(cn, ou string, memberIds []string) *errors.Error
		CreateGroup(T) *errors.Error
		Delete(cn, ou string) *errors.Error
		AddMembers(cn, ou string, memberIds []string) *errors.Error
		RemoveMembers(cn, ou string, memberIds []string) *errors.Error
		GetSearchRequest(cn, ou, groupSearchFilter string) *ldap.SearchRequest
		ParseSearchResult(result *ldap.SearchResult) []T
		ModifyGroup(group, old_group T) *errors.Error
		ValidateGroup(T) *errors.Error
		GetAddRequest(T) *ldap.AddRequest
		GetDeleteRequest(cn, ou string) *ldap.DelRequest
		GetModifyRequest(cn, ou string) *ldap.ModifyRequest
		GetDN(cn, ou string) string
		GetUniqueMemberDn(memberId string) string
		SetDefaults(*T)
	}

	IGroup interface {
		GetMembers() []string
	}
)
