package ldap

import (
	"strings"
	"testing"
)

func newTestClient() *Client {
	return NewClient(&ConfigLdap{
		Protocol:                 ProtocolLdaps,
		Hostname:                 "ldap.example.test",
		Port:                     "636",
		BaseDN:                   "dc=example,dc=test",
		UserBaseDN:               "ou=Users,dc=example,dc=test",
		GroupBaseDN:              "ou=Groups,dc=example,dc=test",
		BindUser:                 "cn=admin,dc=example,dc=test",
		BindPassword:             "unused",
		UserDnAttribute:          "mail",
		MailGroupDnAttribute:     "mail",
		SecurityGroupDnAttribute: "cn",
		MailDomain:               "example.test",
	}, &ConfigMail{}, UnitTesting())
}

// RDN values are escaped: a comma cannot move the entry to another subtree.
func TestUserDnIsEscaped(t *testing.T) {
	c := newTestClient()
	um := NewUsersManager(c)
	dn := um.getDN("mail", "x@example.test,ou=Admins", "")
	if !strings.HasPrefix(dn, "mail=x@example.test\\,ou=Admins,") {
		t.Fatalf("DN not escaped: %s", dn)
	}
}

func TestGroupDnIsEscaped(t *testing.T) {
	c := newTestClient()
	gm := NewGroupSecManager(c)
	dn := gm.GetDN("cn", "team,ou=Admins", "it+cn=x")
	if !strings.HasPrefix(dn, "cn=team\\,ou=Admins,ou=it\\+cn=x,") {
		t.Fatalf("DN not escaped: %s", dn)
	}
	member := gm.GetUniqueMemberDn("bob,ou=Admins")
	if !strings.HasPrefix(member, "uid=bob\\,ou=Admins,") {
		t.Fatalf("member DN not escaped: %s", member)
	}
}

// Fields tagged diff:"...,immutable" are never written by ModifyUser.
func TestImmutableAttributesComputed(t *testing.T) {
	um := NewUsersManager(newTestClient())
	for _, attr := range []string{"uid", "mail", "homeDirectory", "mailMessageStore", "storageBaseDirectory", "mailboxFormat"} {
		if !um.immutableAttributes[attr] {
			t.Errorf("%s should be immutable", attr)
		}
	}
	for _, attr := range []string{"cn", "sn", "displayName", "givenName"} {
		if um.immutableAttributes[attr] {
			t.Errorf("%s should be modifiable", attr)
		}
	}
}

// The clear-text password is never part of the Add request.
func TestAddRequestHasNoPassword(t *testing.T) {
	um := NewUsersManager(newTestClient())
	user := User{Uid: "alice", Cn: "Alice", Sn: "A", Mail: "alice@example.test", UserPassword: "s3cret!!"}
	um.SetDefaults(&user)
	ar := um.getAddRequest(user)
	if ar == nil {
		t.Fatal("nil add request")
	}
	for _, a := range ar.Attributes {
		if a.Type == userPasswordAttr {
			t.Fatal("userPassword must not be written in clear by the Add request")
		}
	}
}

func TestPasswordNotEchoedInError(t *testing.T) {
	um := NewUsersManager(newTestClient())
	err := um.validatePassword("abc")
	if err == nil || strings.Contains(err.Message, "abc") {
		t.Fatalf("rejected password must not be echoed: %v", err)
	}
}

func TestValidateUserRejectsDnInjectionInMail(t *testing.T) {
	um := NewUsersManager(newTestClient())
	user := User{Cn: "X", Sn: "Y", Mail: "x@example.test,ou=Admins", UserPassword: "s3cret!!"}
	if err := um.validateUser(user); err == nil {
		t.Fatal("mail with DN separators must be rejected")
	}
}

func TestDeleteByEmailAcceptsEmail(t *testing.T) {
	um := NewUsersManager(newTestClient())
	if err := um.validateEmail("bob@example.test"); err != nil {
		t.Fatalf("valid email rejected: %v", err)
	}
}
