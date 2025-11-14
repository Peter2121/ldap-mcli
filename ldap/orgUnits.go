package ldap

import (
	"github.com/atselvan/go-utils/utils/errors"
	"github.com/go-ldap/ldap/v3"
)

type (
	// OrganizationalUnitsManager describes the interface which needs to be implemented for performing operations on
	// LDAP organizational units.
	OrganizationalUnitsManager interface {
		GetAll() ([]string, *errors.Error)
	}

	// organizationalUnitsManager implements the operations to be performed on an LDAP organizational unit.
	organizationalUnitsManager struct {
		Client *Client
	}
)

// GetAll gets all the organizations unit entries from LDAP using GroupBaseDN as the root dn.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (oum *organizationalUnitsManager) GetAll() ([]string, *errors.Error) {
	sr := oum.getSearchRequest()

	result, cErr := oum.Client.doLDAPSearch(sr)
	if cErr != nil {
		return nil, cErr
	}

	return oum.parseSearchResult(result), nil
}

// getSearchRequest returns a ldap search request to get all organization units.
func (oum *organizationalUnitsManager) getSearchRequest() *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		oum.Client.ConfigLdap.GroupBaseDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		orgUnitSearchFilter,
		[]string{OrganizationalUnitAttr},
		nil,
	)
}

// parseSearchResult parses the ldap search result and returns a list of organization unit names.
func (oum *organizationalUnitsManager) parseSearchResult(result *ldap.SearchResult) []string {
	var organizationalUnits []string
	for _, entry := range result.Entries {
		organizationalUnits = append(organizationalUnits, entry.GetAttributeValue(OrganizationalUnitAttr))
	}
	return organizationalUnits
}
