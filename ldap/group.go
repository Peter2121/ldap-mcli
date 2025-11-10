package ldap

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/logger"
	"github.com/atselvan/go-utils/utils/slice"
)

func validateGroup(cn string) *errors.Error {
	var missingParams []string

	if strings.TrimSpace(cn) == "" {
		missingParams = append(missingParams, CommonNameAttr)
	}
	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	return nil
}

func validateGroupStatus(status string) bool {
	if (status == GroupStatusActive) || (status == GroupStatusDisabled) {
		return true
	} else {
		return false
	}
}

func GetMembers[T IGroup](g T) []string {
	return g.GetMembers()
}

// GetAll retrieves all the group entries from the groupBaseDn set in the client Config
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func GetAll[T any, S GroupsManager[T]](mgr *S) ([]T, *errors.Error) {
	return (*mgr).Get("", "")
}

// GetFilteredGroups will filter and get a list of group entries based on the searchFilter
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func GetFilteredGroups[T any, S GroupsManager[T]](mgr *S, searchFilter string) ([]T, *errors.Error) {
	result, err := (*mgr).GetClient().doLDAPSearch((*mgr).GetSearchRequest("", "", searchFilter))
	if err != nil {
		return nil, err
	}
	return (*mgr).ParseSearchResult(result), nil
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
func Create[T any, S GroupsManager[T]](mgr *S, cn, ou string, memberIds []string) *errors.Error {
	if err := validateGroup(cn); err != nil {
		return err
	}
	if len(memberIds) == 0 {
		memberIds = append(memberIds, noSuchUserGroupMemberCn)
	}
	return nil
}

func CreateGroup[T any, S GroupsManager[T]](mgr *S, group T) *errors.Error {
	if err := (*mgr).ValidateGroup(group); err != nil {
		return err
	}
	(*mgr).SetDefaults(&group)
	cErr := (*mgr).GetClient().doLDAPAdd((*mgr).GetAddRequest(group))
	return cErr
}

// Delete deletes an existing group entry from LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit from which the group should be deleted
//
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func Delete[T any, S GroupsManager[T]](mgr *S, cn, ou string) *errors.Error {
	if err := validateGroup(cn); err != nil {
		return err
	}
	if cErr := (*mgr).GetClient().doLDAPDelete((*mgr).GetDeleteRequest(cn, ou)); cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return errors.NotFoundError(fmt.Sprintf(groupNotFoundMsg, "cn", cn, ou))
		} else {
			return cErr
		}
	}
	return nil
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
func AddMembers[T IGroup, S GroupsManager[T]](mgr *S, cn, ou string, memberIds []string) *errors.Error {
	var uniqueMembers []string
	if err := validateGroup(cn); err != nil {
		return err
	}
	result, cErr := (*mgr).Get(cn, ou)
	if cErr != nil {
		return cErr
	}
	group := result[0]
	mr := (*mgr).GetModifyRequest(cn, ou)
	for _, memberId := range memberIds {
		uniqueMember := (*mgr).GetUniqueMemberDn(strings.ToUpper(memberId))
		if !slice.EntryExists(GetMembers(group), uniqueMember) {
			logger.Info(fmt.Sprintf(uniqueMemberWillBeAddedToGroupMsg, uniqueMember, (*mgr).GetDN(cn, ou)))
			uniqueMembers = append(uniqueMembers, uniqueMember)
		}
	}
	if len(uniqueMembers) > 0 {
		mr.Add(uniqueMemberAttr, uniqueMembers)
	}
	if len(GetMembers(group))+len(uniqueMembers) >= 2 {
		uniqueMember := (*mgr).GetUniqueMemberDn(noSuchUserGroupMemberCn)
		mr.Delete(uniqueMemberAttr, []string{uniqueMember})
	}
	if cErr := (*mgr).GetClient().doLDAPModify(mr); cErr != nil {
		return cErr
	}
	return nil
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
func RemoveMembers[T IGroup, S GroupsManager[T]](mgr *S, cn, ou string, memberIds []string) *errors.Error {
	var uniqueMembers []string
	if err := validateGroup(cn); err != nil {
		return err
	}
	result, cErr := (*mgr).Get(cn, ou)
	if cErr != nil {
		return cErr
	}
	group := result[0]
	mr := (*mgr).GetModifyRequest(cn, ou)
	for _, memberId := range memberIds {
		uniqueMember := (*mgr).GetUniqueMemberDn(strings.ToUpper(memberId))
		if slice.EntryExists(GetMembers(group), uniqueMember) {
			if memberId != noSuchUserGroupMemberCn {
				logger.Info(fmt.Sprintf(uniqueMemberWillBeRemovedFromGroupMsg, uniqueMember, (*mgr).GetDN(cn, ou)))
			}
			uniqueMembers = append(uniqueMembers, uniqueMember)
		}
	}
	if len(uniqueMembers) > 0 {
		mr.Delete(uniqueMemberAttr, uniqueMembers)
	}
	if len(GetMembers(group))-len(uniqueMembers) == 0 {
		uniqueMember := (*mgr).GetUniqueMemberDn(strings.ToUpper(noSuchUserGroupMemberCn))
		mr.Add(uniqueMemberAttr, []string{uniqueMember})
	}
	if cErr := (*mgr).GetClient().doLDAPModify(mr); cErr != nil {
		return cErr
	}
	return nil
}
