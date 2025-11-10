package ldap

import (
	"fmt"
	"strings"

	"github.com/atselvan/go-utils/utils/config"
	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/logger"
	"github.com/atselvan/go-utils/utils/slice"
	"github.com/go-ldap/ldap/v3"
)

const (
	ldapUrlFormat = "%s://%s:%s"

	// TODO: User reflection to get some info from struct tags
	userIdAttr               = "uid"
	CommonNameAttr           = "cn"
	familyNameAttr           = "sn"
	displayNameAttr          = "displayName"
	MailAttr                 = "mail"
	userPasswordAttr         = "userPassword"
	statusAttr               = "accountStatus"
	OrganizationalUnitAttr   = "ou"
	uniqueMemberAttr         = "member"
	objectClassAttr          = "objectClass"
	enabledServiceAttr       = "enabledService"
	shadowAddressAttr        = "shadowAddress"
	domainAdminAttr          = "domainGlobalAdmin"
	givenNameAttr            = "givenName"
	homeDirectoryAttr        = "homeDirectory"
	mailboxFormatAttr        = "mailboxFormat"
	mailMessageStoreAttr     = "mailMessageStore"
	mailQuotaAttr            = "mailQuota"
	storageBaseDirectoryAttr = "storageBaseDirectory"

	orgUnitSearchFilter   = "(&(objectClass=organizationalUnit))"
	groupSecSearchFilter  = "(&(objectClass=groupOfNames))"
	groupMailSearchFilter = "(&(objectClass=mailList))"
	userSearchFilter      = "(&(objectClass=inetOrgPerson))"

	ProtocolLdap                      = "ldap"
	ProtocolLdaps                     = "ldaps"
	UniqueMemberAttrValuePrefix       = userIdAttr + "="
	OrganizationalUnitAttrValuePrefix = OrganizationalUnitAttr + "="
	//WildcardSecGroupsSearchFilter     = "(&(cn=%s*)(objectClass=groupOfNames))"
	//WildcardMailGroupsSearchFilter    = "(&(cn=%s*)(objectClass=mailList))"
	MailGroupsSearchFilter  = "(&(%s=%s)(objectClass=mailList))"
	SecGroupsOuSearchFilter = "(&(%s=%s)(ou=%s)(objectClass=groupOfNames))"
	SecGroupsSearchFilter   = "(&(%s=%s)(objectClass=groupOfNames))"
	UserSearchFilter        = "(&(%s=%s)(objectClass=inetOrgPerson))"

	connectionMsg        = "Connecting to the LDAP server %s..."
	connectionSuccessMsg = "Connected to the LDAP server"
)

var (
	validProtocols = []string{
		ProtocolLdap,
		ProtocolLdaps,
	}
)

type (
	// Config represents LDAP connection details.
	Config struct {
		Protocol     string `json:"protocol" yaml:"protocol" mapstructure:"LDAP_PROTOCOL" required:"true"`
		Hostname     string `json:"hostname" yaml:"hostname" mapstructure:"LDAP_HOSTNAME" required:"true"`
		Port         string `json:"port" yaml:"port" mapstructure:"LDAP_PORT" required:"true"`
		BaseDN       string `json:"baseDN" yaml:"baseDN" mapstructure:"LDAP_BASE_DN" required:"true"`
		UserBaseDN   string `json:"userBaseDN" yaml:"userBaseDN" mapstructure:"LDAP_USER_BASE_DN" required:"true"`
		GroupBaseDN  string `json:"groupBaseDN" yaml:"groupBaseDN" mapstructure:"LDAP_GROUP_BASE_DN" required:"true"`
		BindUser     string `json:"bindUser" required:"true"`
		BindPassword string `json:"bindPassword" required:"true"`
	}

	// Client represents the development ldap client.
	Client struct {
		Config
		ldapClient  ldap.Client
		unitTesting bool

		// supported interfaces
		OrganizationalUnits OrganizationalUnitsManager
		GroupsSec           GroupsManager[GroupSec]
		GroupsMail          GroupsManager[GroupMail]
		Users               UsersManager
	}

	// ClientOption to configure API client
	ClientOption func(*Client)
)

// NewClient returns a default ldap client.
// You can override some default configuration using ClientOption.
func NewClient(config *Config, opts ...ClientOption) *Client {
	c := &Client{
		ldapClient: &ldap.Conn{},
		Config:     *config,
	}

	// setting default protocol
	c = c.SetProtocol(config.Protocol)

	// supported interfaces
	c.OrganizationalUnits = &organizationalUnitsManager{Client: c}
	c.GroupsSec = NewGroupSecManager(c)
	c.GroupsMail = NewGroupMailManager(c)
	c.Users = NewUsersManager(c)

	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SetProtocol sets the protocol in the Client Config.
func (c *Client) SetProtocol(protocol string) *Client {
	if slice.EntryExists(validProtocols, protocol) {
		c.Config.Protocol = protocol
	} else {
		c.Config.Protocol = ProtocolLdaps
	}
	return c
}

// SetHostname sets the hostname in the Client Config.
func (c *Client) SetHostname(hostname string) *Client {
	c.Config.Hostname = hostname
	return c
}

// SetPort sets the LDAP server port in the Config.
func (c *Client) SetPort(port string) *Client {
	c.Config.Port = port
	return c
}

// SetBindCredentials sets the LDAP basic authentication/bind credentials for LDAP in the config.
func (c *Client) SetBindCredentials(bindUser, bindPassword string) *Client {
	c.Config.BindUser = bindUser
	c.Config.BindPassword = bindPassword
	return c
}

// WithLDAPClient overrides the default ldap.Client.
func WithLDAPClient(ldapClient ldap.Client) ClientOption {
	return func(c *Client) {
		c.ldapClient = ldapClient
	}
}

// WithOrganisationUnitsManager overrides the default OrganizationalUnitsManager.
// This function can be used while mocking the OrganizationalUnitsManager interface for unit testing.
func WithOrganisationUnitsManager(oum OrganizationalUnitsManager) ClientOption {
	return func(c *Client) {
		c.OrganizationalUnits = oum
	}
}

// WithGroupsManager overrides the default GroupsManager.
// This function can be used while mocking the GroupsManager interface for unit testing.
/*
func WithGroupsSecManager(gm GroupManager) ClientOption {
	return func(c *Client) {
		c.GroupsSec = gm
	}
}
*/
// WithUsersManager overrides the default UsersManager.
// This function can be used while mocking the UsersManager interface for unit testing.
func WithUsersManager(um UsersManager) ClientOption {
	return func(c *Client) {
		c.Users = um
	}
}

// UnitTesting is a client option that will skip LDAP Dial and DialTls during unit testing.
// This function is added because it is currently not possible to mock Dial and DialTls.
func UnitTesting() ClientOption {
	return func(c *Client) {
		c.unitTesting = true
	}
}

// doLDAPSearch searches for entries in LDAP.
func (c *Client) doLDAPSearch(sr *ldap.SearchRequest) (*ldap.SearchResult, *errors.Error) {
	cErr := c.connect()
	if cErr != nil {
		return nil, cErr
	}
	defer c.ldapClient.Close()
	result, err := c.ldapClient.Search(sr)
	if err != nil {
		return nil, c.handleLdapError(err)
	}
	return result, nil
}

// doLDAPAdd adds a new entry in LDAP.
func (c *Client) doLDAPAdd(ar *ldap.AddRequest) *errors.Error {
	cErr := c.connect()
	if cErr != nil {
		return cErr
	}
	defer c.ldapClient.Close()
	if err := c.ldapClient.Add(ar); err != nil {
		return c.handleLdapError(err)
	}
	return nil
}

// doLDAPDelete removes an existing entry in LDAP.
func (c *Client) doLDAPDelete(dr *ldap.DelRequest) *errors.Error {
	cErr := c.connect()
	if cErr != nil {
		return cErr
	}
	defer c.ldapClient.Close()
	if err := c.ldapClient.Del(dr); err != nil {
		return c.handleLdapError(err)
	}
	return nil
}

// doLDAPModify update an existing entry in LDAP.
func (c *Client) doLDAPModify(mr *ldap.ModifyRequest) *errors.Error {
	cErr := c.connect()
	if cErr != nil {
		return cErr
	}
	defer c.ldapClient.Close()
	if err := c.ldapClient.Modify(mr); err != nil {
		return c.handleLdapError(err)
	}
	return nil
}

// doLDAPModify update an existing entry in LDAP.
func (c *Client) doLDAPPasswordModify(pmr *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, *errors.Error) {
	cErr := c.connect()
	if cErr != nil {
		return nil, cErr
	}
	defer c.ldapClient.Close()
	result, err := c.ldapClient.PasswordModify(pmr)
	if err != nil {
		return nil, c.handleLdapError(err)
	}
	return result, nil
}

// connect validates the connection details and attempts to connect to the ldap server.
// The method returns an error if connection to the ldap server fails.
func (c *Client) connect() *errors.Error {
	if cErr := c.validate(); cErr != nil {
		return cErr
	}

	ldapUrl := fmt.Sprintf(ldapUrlFormat, c.Config.Protocol, c.Config.Hostname, c.Config.Port)
	logger.Debug(fmt.Sprintf(connectionMsg, ldapUrl))

	if !c.unitTesting {
		if cErr := c.dial(); cErr != nil {
			return cErr
		}
	}

	if cErr := c.bind(); cErr != nil {
		return cErr
	}
	logger.Debug(connectionSuccessMsg)

	return nil
}

// validate validates the ldap client configuration.
func (c *Client) validate() *errors.Error {
	if cErr := config.Validate(&c.Config); cErr != nil {
		return errors.BadRequestError(cErr.Message)
	}
	return nil
}

// dial creates a new connection with an LDAP server based on the client Config.
func (c *Client) dial() *errors.Error {
	var err error
	if c.Config.Protocol == "ldap" {
		c.ldapClient, err = ldap.Dial("tcp", fmt.Sprintf("%s:%s", c.Config.Hostname, c.Config.Port))
	} else {
		c.ldapClient, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%s", c.Config.Hostname, c.Config.Port), nil)
	}
	if err != nil {
		return c.handleLdapError(err)
	}
	return nil
}

// bind authenticates to an LDAP server using the bind credentials set in the client Config.
func (c *Client) bind() *errors.Error {
	if err := c.ldapClient.Bind(c.Config.BindUser, c.Config.BindPassword); err != nil {
		return c.handleLdapError(err)
	}
	return nil
}

// handleLdapError validates the errors returned by the ldap client and returns the appropriate rest error.
func (c *Client) handleLdapError(err error) *errors.Error {
	errStr := err.Error()

	switch {

	case strings.Contains(errStr, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials]),
		strings.Contains(errStr, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidDNSyntax]):
		return errors.UnauthorizedError(ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials])

	case strings.Contains(errStr, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights]):
		return errors.ForbiddenError(ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights])

	case strings.Contains(errStr, ldap.LDAPResultCodeMap[ldap.LDAPResultEntryAlreadyExists]):
		return errors.BadRequestError(ldap.LDAPResultCodeMap[ldap.LDAPResultEntryAlreadyExists])

	case strings.Contains(errStr, ldap.LDAPResultCodeMap[ldap.LDAPResultNoSuchObject]):
		return errors.NotFoundError(ldap.LDAPResultCodeMap[ldap.LDAPResultNoSuchObject])

	default:
		logger.Error(err.Error())
		return errors.InternalServerError(err.Error())
	}
}
