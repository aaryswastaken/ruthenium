// Database mannager (this is gonna be fun lol)

use std::fs;

use ldap3_proto::simple::*;
use ldap3_proto::simple::LdapFilter::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Whitelist {
    pub whitelisted: Vec<User>,
    pub dc: String
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub username: String,
    pub uid: i64
}

pub trait DynamicObject {
    fn get_ldap_entry(&mut self, dc: &String) -> LdapSearchResultEntry;
}

pub trait ExtendedLdapSearchResultEntry {
    fn has_base(&mut self, base: &String) -> bool;
    fn matches_filter(&mut self, filter: &LdapFilter) -> bool;
    fn has_attribute(&mut self, attribute_name: &String) -> bool;
    fn get_attribute(&mut self, attribute_name: &String) -> Vec<String>;
}

impl DynamicObject for User {
    fn get_ldap_entry(&mut self, dc: &String) -> LdapSearchResultEntry {
        LdapSearchResultEntry {
            dn: format!("cn={},{}", self.username, dc),
            attributes: vec![
                LdapPartialAttribute {
                    atype: "objectClass".to_string(),
                    vals: vec!["inetOrgPerson".to_string(), "posixAccount".to_string()]
                },
                LdapPartialAttribute {
                    atype: "cn".to_string(),
                    vals: vec![self.username.to_string()]
                },
                LdapPartialAttribute {
                    atype: "gidNumber".to_string(),
                    vals: vec![self.uid.to_string()]
                },
                LdapPartialAttribute {
                    atype: "uid".to_string(),
                    vals: vec![self.username.to_string()]
                },
                LdapPartialAttribute {
                    atype: "uidNumber".to_string(),
                    vals: vec![self.uid.to_string()]
                }
            ]
        }
    }
}

impl ExtendedLdapSearchResultEntry for LdapSearchResultEntry {
    fn has_base(&mut self, base: &String) -> bool {
        // let base_split = base.split(',').into_iter().rev();
        // let self_dn_split:Vec<&str> = self.dn.split(',').into_iter().rev().collect();

        // return base_split.enumerate().all(|(id, base)| self_dn_split[id] == base);
        return self.dn == base.clone() || (self.dn.split(",").collect::<Vec<String>>().len() == base.split(",").collect::<Vec<String>>().len() + 1 && self.dn.contains(base))
    }

    fn matches_filter(&mut self, filter: &LdapFilter) -> bool {
        match filter {
            And(filters) => filters.iter().all(|e| self.matches_filter(&e)),
            Or(filters)  => filters.iter().any(|e| self.matches_filter(&e)),
            Not(not) => !self.matches_filter(&not),

            Equality(str1, str2) => {
                if self.has_attribute(&str1) {
                    self.get_attribute(&str1).contains(str2)
                } else {
                    false
                }},
            Substring(_str1, _idk) => true,  // ?????????????????????????????????????????

            Present(str1) => self.has_attribute(&str1)
        }
    }

    fn has_attribute(&mut self, attribute_name: &String) -> bool {
        self.attributes.clone().into_iter().any(|attribute| attribute.atype == attribute_name.clone())
    }

    fn get_attribute(&mut self, attribute_name: &String) -> Vec<String> {
        self.attributes.clone().into_iter().filter(|attribute| attribute.atype == attribute_name.clone()).map(|a| a.vals).flatten().collect::<Vec<String>>()
    }
}

pub struct ObjectManager {
    pub dc: String,
    pub static_objects: Vec<LdapSearchResultEntry>,
    pub dynamic_objects: Vec<User> // need to do this procedurally for every struct implementing DynamicObject trat
}

impl Whitelist {
    pub fn new() -> Whitelist{
        Whitelist{whitelisted: vec![], dc: "".to_string()}
    }

    pub fn read_from_file(filename: String, dc: String) -> Whitelist {
        let content = fs::read_to_string(filename).expect("Something went wrong while trying to read the file");
    
        let whitelist = Whitelist{whitelisted: content.lines().enumerate().map(|(uid, name)| User{username: name.to_string(), uid: uid as i64}).collect::<Vec<User>>(), dc: dc};
    
        return whitelist
    }
}

impl User {
}

impl ObjectManager {
    pub fn new(dc: String) -> ObjectManager {
        ObjectManager {
            dc: dc,
            static_objects: vec![],
            dynamic_objects: vec![]
        }
    }

    pub fn initialise(filename: String, dc: String) -> ObjectManager {
        let mut instance = ObjectManager::new(dc.clone());

        instance.dynamic_objects = Whitelist::read_from_file(filename, dc).whitelisted;

        instance.static_objects = vec![
            LdapSearchResultEntry {
                dn: "".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["RutheniumLDAPRootDSE".to_string(),"top".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "namingContexts".to_string(),
                        vals: vec!["dc=example,dc=org".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "entryDN".to_string(),
                        vals: vec!["".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "subschemaSubentry".to_string(),
                        vals: vec!["cn=Subschema".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "structuralObjectClass".to_string(),
                        vals: vec!["RutheniumLDAPRootDSE".to_string()]
                    }
                ]
            },
            LdapSearchResultEntry {
                dn: "dc=example,dc=org".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["dcObject".to_string(),"organization".to_string()]
                    },
                    LdapPartialAttribute {                     
                        atype: "dc".to_string(),
                        vals: vec!["example".to_string()],
                    },
                    LdapPartialAttribute {                     
                        atype: "o".to_string(),
                        vals: vec!["example".to_string()],
                    },
                ]
            },
            LdapSearchResultEntry {
                dn: "ou=users,dc=example,dc=org".to_string(),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectClass".to_string(),
                        vals: vec!["organizationalUnit".to_string()]
                    },
                    LdapPartialAttribute {
                        atype: "ou".to_string(),
                        vals: vec!["users".to_string()]
                    }
                ]
            }
        ];

        return instance;
    }

    pub fn do_search(&mut self, lsr: &SearchRequest) -> Vec<LdapMsg> {
        let mut results: Vec<LdapSearchResultEntry> = Vec::new();

        let mut objects: Vec<LdapSearchResultEntry> = self.static_objects.clone();
        let dyn_objects: Vec<User> = self.dynamic_objects.clone();
        objects.append(&mut (dyn_objects.into_iter().map(|mut dyn_o| dyn_o.get_ldap_entry(&self.dc)).collect::<Vec<LdapSearchResultEntry>>()));

        // fill the result vector
        for mut o in objects.into_iter() {
            if o.has_base(&lsr.base) && o.matches_filter(&lsr.filter) {
                results.push(o.clone());
            }
        }

        println!("Finished query with: {}", results.clone().iter().map(|e| if e.dn == "" {"Empty".to_string()} else {e.dn.clone()}).collect::<Vec<String>>().join(" & "));

        let mut out = results.iter().map(|e| lsr.gen_result_entry(e.clone())).collect::<Vec<LdapMsg>>();
        out.push(lsr.gen_success());

        return out;
    }
}