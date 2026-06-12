# Lab: LDAP Authentication with Legacy TLS on OpenShift 4.15+

## Background

This lab reproduces a real-world issue where an **Active Directory using TLS 1.2 with RSA Key Exchange cipher suites** stops working after upgrading to OpenShift 4.15+. The root cause is that Go 1.22 — which ships with OCP 4.15 — silently dropped support for `TLS_RSA_WITH_*` cipher suites ([Go 1.22 changelog](https://go.dev/doc/go1.22#crypto/tls)).

The symptom is deceptively simple: users who were logging in just fine suddenly can't authenticate after an OCP upgrade. The OAuth server logs show `Network Error: EOF` — a TLS handshake failure that looks like a network problem but is actually a cipher suite incompatibility.

### What this lab demonstrates

| Scenario | TLS | Cipher | OCP OAuth (Go 1.22+) | Keycloak (Java) |
|---|---|---|---|---|
| Legacy LDAP — RSA Kx only | TLS 1.2 | TLS_RSA_WITH_AES_256_GCM_SHA384 | **FAILS** — Network Error: EOF | Works fine |
| Legacy LDAP — with ECDHE fix | TLS 1.2 | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | **Works** | Works fine |
| Modern LDAP — TLS 1.3 | TLS 1.3 | ECDHE only | **Works** | Works fine |

The key insight: Keycloak uses Java's LDAP stack, which doesn't have Go's restriction, so the same broken LDAP server works fine when accessed through Keycloak. This opens up a useful workaround path when you can't touch the AD.

### Solutions covered

* **Option A** — Enable ECDHE cipher suites on the LDAP/AD server → **Validated ✓**
* **Option B** — Migrate to TLS 1.3 → **Validated ✓** (via openldap-modern)
* **Option C** — Put Keycloak/RHBK in front as an OIDC broker → **Validated ✓**

---

## Prerequisites

* OpenShift CRC 4.15+ (this lab was built on CRC 4.21 — note that OCP 4.14 is **not** affected)
* `oc` CLI installed and configured
* cluster-admin access

```bash
oc login -u kubeadmin -p <password> https://api.crc.testing:6443 --insecure-skip-tls-verify
```

---

## Part 1 — Base Infrastructure

### 1.1 Namespace and Service Accounts

```bash
oc new-project legacy-auth
oc create sa openldap-legacy-sa -n legacy-auth
oc create sa openldap-modern-sa -n legacy-auth
oc adm policy add-scc-to-user anyuid -z openldap-legacy-sa -n legacy-auth
oc adm policy add-scc-to-user anyuid -z openldap-modern-sa -n legacy-auth
```

### 1.2 Generate TLS Certificates

Both LDAP servers share a common CA. This simplifies trust configuration later — you only need to register one CA with OCP OAuth and Keycloak.

The server certificates **must** include `keyEncipherment` in the Key Usage extension. Without it, RSA key exchange cipher suites fail at the TLS handshake level regardless of what the server advertises. This is a common gotcha when generating certs manually.

```bash
# Shared CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt -subj "/CN=ldap-lab-ca"

# Legacy LDAP certificate
openssl genrsa -out ldap-legacy.key 2048
openssl req -new -key ldap-legacy.key -out ldap-legacy.csr \
  -subj "/CN=openldap-legacy.legacy-auth.svc.cluster.local"
cat > ldap-legacy-ext.cnf <<EOF
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:openldap-legacy.legacy-auth.svc.cluster.local, \
  DNS:openldap-legacy, DNS:localhost
EOF
openssl x509 -req -in ldap-legacy.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out ldap-legacy.crt -days 3650 -sha256 \
  -extfile ldap-legacy-ext.cnf

# Modern LDAP certificate
openssl genrsa -out ldap-modern.key 2048
openssl req -new -key ldap-modern.key -out ldap-modern.csr \
  -subj "/CN=openldap-modern.legacy-auth.svc.cluster.local"
cat > ldap-modern-ext.cnf <<EOF
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:openldap-modern.legacy-auth.svc.cluster.local, \
  DNS:openldap-modern, DNS:localhost
EOF
openssl x509 -req -in ldap-modern.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out ldap-modern.crt -days 3650 -sha256 \
  -extfile ldap-modern-ext.cnf
```

### 1.3 Create Secrets

```bash
oc create secret generic openldap-legacy-certs -n legacy-auth \
  --from-file=ldap.crt=ldap-legacy.crt \
  --from-file=ldap.key=ldap-legacy.key \
  --from-file=ca.crt=ca.crt

oc create secret generic openldap-modern-certs -n legacy-auth \
  --from-file=ldap.crt=ldap-modern.crt \
  --from-file=ldap.key=ldap-modern.key \
  --from-file=ca.crt=ca.crt
```

### 1.4 Persistent Volumes

```yaml
# File: pvcs.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: openldap-legacy-data
  namespace: legacy-auth
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: openldap-modern-data
  namespace: legacy-auth
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
```

```bash
oc apply -f pvcs.yaml
```

---

## Part 2 — Deploy Legacy OpenLDAP (TLS 1.2 + RSA Kx)

This server intentionally reproduces the broken configuration. The `+RSA` token in GnuTLS's priority string means "RSA Key Exchange" — the static RSA cipher suites that Go 1.22 dropped. There's no `+ECDHE` here, so Go 1.22+ clients will fail to negotiate.

```yaml
# File: openldap-legacy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openldap-legacy
  namespace: legacy-auth
  labels:
    app: openldap-legacy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openldap-legacy
  template:
    metadata:
      labels:
        app: openldap-legacy
    spec:
      serviceAccountName: openldap-legacy-sa
      initContainers:
      - name: copy-certs
        image: osixia/openldap:1.2.5
        command: ["sh", "-c"]
        args:
        - |
          cp /mnt/secret/ldap.crt /mnt/certs/ldap.crt
          cp /mnt/secret/ldap.key /mnt/certs/ldap.key
          cp /mnt/secret/ca.crt /mnt/certs/ca.crt
        volumeMounts:
        - name: secret-certs-volume
          mountPath: /mnt/secret
        - name: writeable-certs-volume
          mountPath: /mnt/certs
      containers:
      - name: openldap
        image: osixia/openldap:1.2.5
        securityContext:
          runAsUser: 0
        ports:
        - containerPort: 389
          name: ldap
        - containerPort: 636
          name: ldaps
        env:
        - name: LDAP_ORGANISATION
          value: "Legacy Lab"
        - name: LDAP_DOMAIN
          value: "legacy.local"
        - name: LDAP_ADMIN_PASSWORD
          value: "AdminPass123!"
        - name: LDAP_TLS
          value: "true"
        - name: LDAP_TLS_PROTOCOL_MIN
          value: "3.3"                    # TLS 1.2
        # ┌──────────────────────────────────────────────────────────┐
        # │  THIS IS THE CIPHER SUITE THAT CAUSES THE PROBLEM:     │
        # │  +RSA = RSA Key Exchange (no Perfect Forward Secrecy)   │
        # │  Go 1.22+ dropped all TLS_RSA_WITH_AES_* suites        │
        # └──────────────────────────────────────────────────────────┘
        - name: LDAP_TLS_CIPHER_SUITE
          value: >-
            NONE:+VERS-TLS1.2:+RSA:+AES-128-GCM:+AES-256-GCM:
            +AES-128-CBC:+AES-256-CBC:+MAC-ALL:+SIGN-ALL:
            +CTYPE-X509:+COMP-ALL
        - name: LDAP_TLS_VERIFY_CLIENT
          value: "never"
        volumeMounts:
        - name: writeable-certs-volume
          mountPath: /container/service/slapd/assets/certs
        - name: openldap-data
          mountPath: /var/lib/ldap
        - name: openldap-config
          mountPath: /etc/ldap/slapd.d
      volumes:
      - name: secret-certs-volume
        secret:
          secretName: openldap-legacy-certs
      - name: writeable-certs-volume
        emptyDir: {}
      - name: openldap-data
        persistentVolumeClaim:
          claimName: openldap-legacy-data
      - name: openldap-config
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: openldap-legacy
  namespace: legacy-auth
spec:
  selector:
    app: openldap-legacy
  ports:
  - name: ldap
    port: 389
    targetPort: 389
  - name: ldaps
    port: 636
    targetPort: 636
```

```bash
oc apply -f openldap-legacy.yaml

# DH parameter generation takes a few minutes under emulation — be patient
oc logs -n legacy-auth deploy/openldap-legacy -f
# Wait until you see: "slapd starting"
```

### Populate legacy users

```bash
oc exec -n legacy-auth deploy/openldap-legacy -c openldap -- \
  ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=legacy,dc=local" -w "AdminPass123!" <<'EOF'
dn: ou=users,dc=legacy,dc=local
objectClass: organizationalUnit
ou: users

dn: uid=bob_legacy,ou=users,dc=legacy,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: bob_legacy
cn: Bob Legacy
sn: Legacy
givenName: Bob
uidNumber: 10001
gidNumber: 10001
homeDirectory: /home/bob_legacy
loginShell: /bin/bash
mail: bob_legacy@legacy.local
userPassword: Password123!

dn: uid=carol_legacy,ou=users,dc=legacy,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: carol_legacy
cn: Carol Legacy
sn: Legacy
givenName: Carol
uidNumber: 10002
gidNumber: 10002
homeDirectory: /home/carol_legacy
loginShell: /bin/bash
mail: carol_legacy@legacy.local
userPassword: Password123!
EOF
```

> **Note**: The script (`demo-script.sh`) uses `posixAccount` and `shadowAccount` objectClasses in addition to `inetOrgPerson`. If you populated manually with only `inetOrgPerson`, you may want to re-populate to match the script. This doesn't affect authentication but ensures consistency.

### Verify

```bash
oc exec -n legacy-auth deploy/openldap-legacy -c openldap -- \
  ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=legacy,dc=local" -w "AdminPass123!" \
  -b "ou=users,dc=legacy,dc=local" uid cn
```

### Confirm the cipher suite

```bash
oc exec -n legacy-auth deploy/openldap-legacy -c openldap -- \
  openssl s_client -connect localhost:636 -tls1_2 </dev/null 2>&1 \
  | grep "Cipher is"
```

Expected output — **RSA Kx, no ECDHE**:

```
New, TLSv1.2, Cipher is AES256-GCM-SHA384
```

---

## Part 3 — Deploy Modern OpenLDAP (TLS 1.3)

### Why a custom image?

The `osixia/openldap` image — even the latest 1.5.0 — ships with slapd 2.4.57 on Debian Buster, which uses an older GnuTLS that doesn't support TLS 1.3. We need to build our own image based on Debian Bookworm, which gives us slapd 2.5.13 with OpenSSL 3.0.

Two non-obvious issues we ran into building this:

**The `back_mdb` module.** In OpenLDAP 2.4.x the MDB backend is compiled in statically — you just declare `database mdb` and it works. In 2.5.x it became a dynamic module. Without `modulepath /usr/lib/ldap` + `moduleload back_mdb` in your `slapd.conf`, `slaptest` fails with `unknown database type "mdb"` and you'll spend a while wondering what went wrong.

**Running as root.** The image mounts TLS certificates from a Kubernetes Secret into an `emptyDir` volume via an init container. When the init container runs as root and copies the files, they're owned by root. If you then try to drop privileges with `-u openldap -g openldap`, slapd can't read the key file and TLS init fails. For a lab environment, just run as root (`runAsUser: 0`, no `-u`/`-g` flags).

### 3.1 Build files

```bash
mkdir -p openldap-modern-build && cd openldap-modern-build
```

**Dockerfile:**

```dockerfile
# File: openldap-modern-build/Dockerfile
FROM debian:bookworm-slim

# slapd 2.5.13 on Bookworm uses OpenSSL 3.0 — TLS 1.3 works out of the box.
# The slapd package installs the back_mdb module under /usr/lib/ldap/.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      slapd ldap-utils openssl procps && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /etc/ldap/certs /var/lib/ldap /etc/ldap/slapd.d && \
    chown -R openldap:openldap /var/lib/ldap /etc/ldap/slapd.d && \
    # Sanity check — if this fails, the entrypoint will fail too
    ls -la /usr/lib/ldap/back_mdb*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 389 636
CMD ["/entrypoint.sh"]
```

**entrypoint.sh:**

```bash
#!/bin/bash
# File: openldap-modern-build/entrypoint.sh
set -e

DOMAIN=${LDAP_DOMAIN:-modern.local}
ADMIN_PASS=${LDAP_ADMIN_PASSWORD:-admin}
SUFFIX="dc=$(echo $DOMAIN | sed 's/\./,dc=/g')"

if [ ! -f /etc/ldap/slapd.d/cn=config.ldif ]; then
  echo "=== Bootstrapping slapd for $DOMAIN (TLS 1.3) ==="

  HASHED_PW=$(slappasswd -s "$ADMIN_PASS")

  cat > /tmp/slapd.conf <<CONF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include /etc/ldap/schema/nis.schema

# ┌─────────────────────────────────────────────────────────────────┐
# │  CRITICAL: In slapd 2.5.x (Debian Bookworm) the MDB backend  │
# │  is a dynamic module. Without these two lines, slaptest fails  │
# │  with: "unknown database type «mdb»"                           │
# └─────────────────────────────────────────────────────────────────┘
modulepath /usr/lib/ldap
moduleload back_mdb

TLSCACertificateFile  /etc/ldap/certs/ca.crt
TLSCertificateFile    /etc/ldap/certs/tls.crt
TLSCertificateKeyFile /etc/ldap/certs/tls.key
TLSProtocolMin        3.4

loglevel stats

database mdb
maxsize  1073741824
suffix   "$SUFFIX"
rootdn   "cn=admin,$SUFFIX"
rootpw   $HASHED_PW
directory /var/lib/ldap

index objectClass eq
index uid eq
CONF

  slaptest -f /tmp/slapd.conf -F /etc/ldap/slapd.d
  chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap
  rm -f /tmp/slapd.conf

  echo "=== Bootstrap complete ==="
fi

# No -u/-g flags: we run as root (runAsUser: 0 in the Deployment).
# Running as the openldap user causes TLS init to fail because the
# cert files in the emptyDir are owned by root (copied by the init container).
exec slapd -h "ldap:/// ldaps:/// ldapi:///" -d 256
```

### 3.2 Build in OpenShift

```bash
oc new-build --binary --name=openldap-modern -n legacy-auth \
  --strategy=docker --docker-image=debian:bookworm-slim

oc start-build openldap-modern \
  --from-dir=openldap-modern-build \
  -n legacy-auth --follow
```

Verify the image landed in the internal registry:

```bash
oc get is openldap-modern -n legacy-auth
```

Expected output:

```
NAME              IMAGE REPOSITORY                                                              TAGS     UPDATED
openldap-modern   image-registry.openshift-image-registry.svc:5000/legacy-auth/openldap-modern  latest   <timestamp>
```

> **Troubleshooting: `unknown database type "mdb"`**
>
> If the pod logs show:
> ```
> slaptest: bad configuration file!
> /tmp/slapd.conf: line XX: unknown database type "mdb"
> ```
> The `moduleload back_mdb` line is missing from the entrypoint's `slapd.conf`. In OpenLDAP 2.4.x (osixia) the MDB backend is statically compiled in, but in **2.5.x (Debian Bookworm) it's a loadable module** that must be explicitly declared.

> **Troubleshooting: TLS init failed with `-u openldap`**
>
> If slapd starts but port 636 doesn't respond and logs show:
> ```
> main: TLS init def ctx failed: -1
> ```
> slapd is trying to read the TLS certificates as the `openldap` user but the files in the emptyDir are root-owned. Fix: run slapd without `-u`/`-g` and set `runAsUser: 0` in the Deployment.

### 3.3 Deploy

```yaml
# File: openldap-modern.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openldap-modern
  namespace: legacy-auth
  labels:
    app: openldap-modern
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openldap-modern
  template:
    metadata:
      labels:
        app: openldap-modern
    spec:
      serviceAccountName: openldap-modern-sa
      initContainers:
      - name: copy-certs
        image: image-registry.openshift-image-registry.svc:5000/legacy-auth/openldap-modern:latest
        command: ["sh", "-c"]
        args:
        - |
          cp /mnt/secret/ldap.crt /mnt/certs/tls.crt
          cp /mnt/secret/ldap.key /mnt/certs/tls.key
          cp /mnt/secret/ca.crt /mnt/certs/ca.crt
          chmod 644 /mnt/certs/*
        volumeMounts:
        - name: secret-certs-volume
          mountPath: /mnt/secret
        - name: writeable-certs-volume
          mountPath: /mnt/certs
      containers:
      - name: openldap
        image: image-registry.openshift-image-registry.svc:5000/legacy-auth/openldap-modern:latest
        securityContext:
          runAsUser: 0
        ports:
        - containerPort: 389
          name: ldap
        - containerPort: 636
          name: ldaps
        env:
        - name: LDAP_DOMAIN
          value: "modern.local"
        - name: LDAP_ADMIN_PASSWORD
          value: "AdminPass123!"
        volumeMounts:
        - name: writeable-certs-volume
          mountPath: /etc/ldap/certs
        - name: openldap-data
          mountPath: /var/lib/ldap
        - name: openldap-config
          mountPath: /etc/ldap/slapd.d
      volumes:
      - name: secret-certs-volume
        secret:
          secretName: openldap-modern-certs
      - name: writeable-certs-volume
        emptyDir: {}
      - name: openldap-data
        persistentVolumeClaim:
          claimName: openldap-modern-data
      - name: openldap-config
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: openldap-modern
  namespace: legacy-auth
spec:
  selector:
    app: openldap-modern
  ports:
  - name: ldap
    port: 389
    targetPort: 389
  - name: ldaps
    port: 636
    targetPort: 636
```

```bash
oc apply -f openldap-modern.yaml
oc rollout status deploy/openldap-modern -n legacy-auth
```

### Populate modern users

```bash
oc exec -n legacy-auth deploy/openldap-modern -c openldap -- \
  ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=modern,dc=local" -w "AdminPass123!" <<'EOF'
dn: ou=users,dc=modern,dc=local
objectClass: organizationalUnit
ou: users

dn: uid=bob_modern,ou=users,dc=modern,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
uid: bob_modern
cn: Bob Modern
sn: Modern
mail: bob@modern.local
userPassword: Password123!

dn: uid=carol_modern,ou=users,dc=modern,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
uid: carol_modern
cn: Carol Modern
sn: Modern
mail: carol@modern.local
userPassword: Password123!
EOF
```

---

## Part 4 — Configure OCP OAuth

### 4.1 Register the CA

```bash
oc create configmap ldap-lab-ca \
  --from-file=ca.crt=ca.crt \
  -n openshift-config
```

### 4.2 Bind password secret

```bash
oc create secret generic ldap-legacy-bind \
  --from-literal=bindPassword='AdminPass123!' \
  -n openshift-config
```

### 4.3 Add the identity providers

```yaml
# File: oauth-ldap.yaml
apiVersion: config.openshift.io/v1
kind: OAuth
metadata:
  name: cluster
spec:
  identityProviders:

  # Existing IDP — leave untouched
  - name: developer
    mappingMethod: claim
    type: HTPasswd
    htpasswd:
      fileData:
        name: htpass-secret

  # Legacy LDAP (TLS 1.2 + RSA Kx — broken with Go 1.22+)
  - name: ldap-legacy
    type: LDAP
    ldap:
      url: "ldaps://openldap-legacy.legacy-auth.svc.cluster.local/ou=users,dc=legacy,dc=local?uid"
      bindDN: "cn=admin,dc=legacy,dc=local"
      bindPassword:
        name: ldap-legacy-bind
      insecure: false
      ca:
        name: ldap-lab-ca
      attributes:
        id: ["uid"]
        email: ["mail"]
        name: ["cn"]
        preferredUsername: ["uid"]

  # Modern LDAP (TLS 1.3 — works fine)
  - name: ldap-modern
    type: LDAP
    ldap:
      url: "ldaps://openldap-modern.legacy-auth.svc.cluster.local/ou=users,dc=modern,dc=local?uid"
      insecure: false
      ca:
        name: ldap-lab-ca
      attributes:
        id: ["uid"]
        email: ["mail"]
        name: ["cn"]
        preferredUsername: ["uid"]
```

```bash
oc apply -f oauth-ldap.yaml

# Wait for the OAuth server to recycle (~30s)
oc get pods -n openshift-authentication -w
```

---

## Part 5 — Install and Configure Keycloak (RHBK)

Keycloak uses Java's LDAP client stack, which still supports RSA Key Exchange cipher suites — so it can talk to the broken LDAP server without issues. OCP then authenticates against Keycloak via OIDC, bypassing the Go TLS restriction entirely.

### 5.1 Install the RHBK operator

```bash
oc new-project keycloak

cat <<'EOF' | oc apply -f -
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: keycloak-og
  namespace: keycloak
spec:
  targetNamespaces:
    - keycloak
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: rhbk-operator
  namespace: keycloak
spec:
  channel: stable-v26
  name: rhbk-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
EOF

# Wait for the operator CSV to reach Succeeded
oc get csv -n keycloak -w
```

### 5.2 Deploy a Keycloak instance

```yaml
# File: keycloak-instance.yaml
apiVersion: k8s.keycloak.org/v2beta1
kind: Keycloak
metadata:
  name: keycloak
  namespace: keycloak
spec:
  instances: 1
  db:
    vendor: dev-file
  http:
    httpEnabled: true
  hostname:
    hostname: keycloak.apps-crc.testing
    strict: false
  startOptimized: false
```

```bash
oc apply -f keycloak-instance.yaml
oc get keycloak keycloak -n keycloak -w
# Wait for: Ready=True
```

> **Important**: The `dev-file` database is **ephemeral** — all Keycloak configuration (federations, clients, users synced from LDAP) is lost when the pod restarts. The demo script handles this by checking and recreating federations and the OIDC client idempotently at the start of each run (see `demo_check_keycloak` in the script).

### 5.3 Get admin credentials

```bash
oc get secret keycloak-initial-admin -n keycloak \
  -o go-template='{{.data.username | base64decode}} / {{.data.password | base64decode}}'
```

### 5.4 A note on the Keycloak 26 admin console

> Keycloak 26 includes a third-party cookie check in the admin console. On first load, it renders a hidden iframe pointing to `/realms/master/protocol/openid-connect/3p-cookies/step1.html` and waits for a postMessage response. If your browser blocks third-party cookies — which most modern browsers do by default, and corporate-managed Chrome tends to enforce strictly — this check times out and you see a `somethingWentWrong` error before you even get to the login form.
>
> The most reliable workaround is to skip the UI entirely and do everything through `kcadm.sh` via `oc exec`. The pattern is:
>
> ```bash
> oc exec -n keycloak keycloak-0 -- bash -c "\
>   mkdir -p /tmp/kc &&\
>   /opt/keycloak/bin/kcadm.sh config credentials \
>     --config /tmp/kc/cfg \
>     --server http://localhost:8080 \
>     --realm master \
>     --user <admin_user> \
>     --password <admin_pass> &&\
>   /opt/keycloak/bin/kcadm.sh <operation> --config /tmp/kc/cfg ..."
> ```
>
> This connects to Keycloak's loopback interface — no TLS, no cookies, no browser involved.

### 5.5 Configure LDAP federations via kcadm.sh

```bash
KC_ADMIN=temp-admin
KC_PASS=<password-from-secret>

# Legacy LDAP federation
oc exec -n keycloak keycloak-0 -- bash -c "\
mkdir -p /tmp/kc &&\
/opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kc/cfg \
  --server http://localhost:8080 \
  --realm master \
  --user $KC_ADMIN \
  --password $KC_PASS &&\
/opt/keycloak/bin/kcadm.sh create components \
  --config /tmp/kc/cfg -r master \
  -s name=ldap-legacy \
  -s providerId=ldap \
  -s providerType=org.keycloak.storage.UserStorageProvider \
  -s 'config.vendor=[\"other\"]' \
  -s 'config.connectionUrl=[\"ldap://openldap-legacy.legacy-auth.svc.cluster.local:389\"]' \
  -s 'config.bindDn=[\"cn=admin,dc=legacy,dc=local\"]' \
  -s 'config.bindCredential=[\"AdminPass123!\"]' \
  -s 'config.usersDn=[\"ou=users,dc=legacy,dc=local\"]' \
  -s 'config.usernameLDAPAttribute=[\"uid\"]' \
  -s 'config.rdnLDAPAttribute=[\"uid\"]' \
  -s 'config.uuidLDAPAttribute=[\"entryUUID\"]' \
  -s 'config.userObjectClasses=[\"inetOrgPerson\"]' \
  -s 'config.searchScope=[\"1\"]' \
  -s 'config.editMode=[\"READ_ONLY\"]' \
  -s 'config.authType=[\"simple\"]' \
  -s 'config.enabled=[\"true\"]'"

# Modern LDAP federation
oc exec -n keycloak keycloak-0 -- bash -c "\
/opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kc/cfg \
  --server http://localhost:8080 \
  --realm master \
  --user $KC_ADMIN \
  --password $KC_PASS &&\
/opt/keycloak/bin/kcadm.sh create components \
  --config /tmp/kc/cfg -r master \
  -s name=ldap-modern \
  -s providerId=ldap \
  -s providerType=org.keycloak.storage.UserStorageProvider \
  -s 'config.vendor=[\"other\"]' \
  -s 'config.connectionUrl=[\"ldap://openldap-modern.legacy-auth.svc.cluster.local:389\"]' \
  -s 'config.bindDn=[\"cn=admin,dc=modern,dc=local\"]' \
  -s 'config.bindCredential=[\"AdminPass123!\"]' \
  -s 'config.usersDn=[\"ou=users,dc=modern,dc=local\"]' \
  -s 'config.usernameLDAPAttribute=[\"uid\"]' \
  -s 'config.rdnLDAPAttribute=[\"uid\"]' \
  -s 'config.uuidLDAPAttribute=[\"entryUUID\"]' \
  -s 'config.userObjectClasses=[\"inetOrgPerson\"]' \
  -s 'config.searchScope=[\"1\"]' \
  -s 'config.editMode=[\"READ_ONLY\"]' \
  -s 'config.authType=[\"simple\"]' \
  -s 'config.enabled=[\"true\"]'"
```

> **Note**: Keycloak connects to LDAP on **port 389 (plaintext)** here, not LDAPS. Pod-to-pod traffic inside the cluster travels over the SDN. More importantly, it completely sidesteps the TLS cipher suite issue — which is exactly the point of this workaround.

### 5.6 Create the OIDC client for OCP

```bash
oc exec -n keycloak keycloak-0 -- bash -c "\
mkdir -p /tmp/kc &&\
/opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kc/cfg \
  --server http://localhost:8080 \
  --realm master \
  --user $KC_ADMIN \
  --password $KC_PASS &&\
/opt/keycloak/bin/kcadm.sh create clients \
  --config /tmp/kc/cfg -r master \
  -s clientId=openshift \
  -s protocol=openid-connect \
  -s enabled=true \
  -s clientAuthenticatorType=client-secret \
  -s secret=ocp-keycloak-secret-2026 \
  -s 'redirectUris=[\"https://oauth-openshift.apps-crc.testing/oauth2callback/keycloak-broker\"]' \
  -s directAccessGrantsEnabled=true \
  -s standardFlowEnabled=true"
```

`directAccessGrantsEnabled=true` enables the Resource Owner Password Credentials (ROPC) grant, which is what `oc login -u <user> -p <pass>` uses when going through an OIDC provider.

### 5.7 Add Keycloak as an OIDC identity provider in OCP

```bash
# Extract the CRC router CA — needed for OCP to trust Keycloak's HTTPS endpoint
oc get secret router-ca -n openshift-ingress-operator \
  -o go-template='{{index .data "tls.crt" | base64decode}}' > /tmp/ingress-ca.pem

oc create configmap keycloak-ca \
  --from-file=ca.crt=/tmp/ingress-ca.pem \
  -n openshift-config

oc create secret generic keycloak-oidc-secret \
  --from-literal=clientSecret=ocp-keycloak-secret-2026 \
  -n openshift-config
```

Add to `spec.identityProviders` in the OAuth object:

```yaml
- name: keycloak-broker
  mappingMethod: claim
  type: OpenID
  openID:
    clientID: openshift
    clientSecret:
      name: keycloak-oidc-secret
    issuer: https://keycloak.apps-crc.testing/realms/master
    ca:
      name: keycloak-ca
    claims:
      preferredUsername: ["preferred_username"]
      name: ["name"]
      email: ["email"]
```

```bash
oc get pods -n openshift-authentication -w
# Wait for oauth-openshift to recycle
```

---

## Part 6 — Running the Demo

The demo is automated by `demo-script.sh`. Source it and call the functions in order.

### 6.1 Script overview

```bash
source demo-script.sh
```

| Function | What it does |
|---|---|
| `pre_demo` | Resets the environment: sets RSA-only cipher suite (broken), cleans PVC, restarts LDAP, repopulates users, recycles OAuth pods, ensures Keycloak has federations + OIDC client |
| `demo_paso1_fallo` | **Step 1 — The failure.** Shows bob_modern succeeds (TLS 1.3) and bob_legacy fails (RSA Kx + Go 1.22). Displays OAuth logs with `Network Error: EOF` |
| `demo_paso2_casoB` | **Step 2 — Case B: TLS 1.3.** Shows the modern server working as a reference for where TLS 1.3 solves the problem |
| `demo_paso3_casoA` | **Step 3 — Case A: Enable ECDHE.** Adds `+ECDHE-RSA` and `+CURVE-ALL` to the legacy server's cipher suite. Restarts LDAP (PVC cleanup), repopulates users, recycles OAuth, and verifies bob_legacy can now authenticate |
| `demo_paso4_casoC` | **Step 4 — Case C: Keycloak broker.** Reverts ldap-legacy to RSA-only (broken again). Shows that carol_legacy can authenticate via Keycloak (Java, no Go restriction) while direct OCP login fails. Prompts for browser-based login via the console |
| `demo_resumen` | Displays all User and Identity objects created during the demo |
| `demo_diag` | Quick diagnostic: pod status, service endpoints, cipher suites, LDAP search, OAuth logs |

### 6.2 Configuration

Edit the three variables at the top of the script before running:

```bash
OCP_API="https://api.crc.testing:6443"
KUBEADMIN_PASS="H5r8u-U2gIe-INVpJ-UME4Q"
KC_PASS="af9af5741acf4b9dbc0b880d94b7d2ea"
```

### 6.3 Demo flow

```bash
# 1. Prepare (run before the customer arrives)
pre_demo

# 2. Show the failure
demo_paso1_fallo

# 3. Show TLS 1.3 works (reference)
demo_paso2_casoB

# 4. Fix A — enable ECDHE on the legacy server
demo_paso3_casoA

# 5. Fix C — Keycloak as OIDC broker (no AD changes needed)
demo_paso4_casoC

# 6. Summary
demo_resumen
```

Each step pauses for you to show the web console and/or explain what happened.

### 6.4 Helper functions

The script includes helper functions that handle the quirks of the lab environment:

| Helper | Purpose |
|---|---|
| `_ldap_cleanup_and_restart` | Scales down openldap-legacy, runs a cleanup pod to `rm -rf /var/lib/ldap/*`, scales back up. Required because `osixia/openldap` refuses to start if the config `emptyDir` is empty but the data PVC has content from a previous run |
| `_wait_for_slapd_tls` | Polls with `openssl s_client` until port 636 accepts connections. Pod `Running` != slapd ready — DH parameter generation can take 2-3 minutes under CRC emulation |
| `_populate_legacy_users` | Creates the LDIF inside the pod and runs `ldapadd`. Includes a verification loop that waits for the users to be searchable |
| `_refresh_oauth` | Deletes the OAuth server pods to force fresh LDAP connections. Go maintains persistent TCP connections; without this step, the OAuth server reuses stale connections from before the LDAP restart and gets `Network Error: EOF` or `No Such Object` |
| `_verify_ldap_from_oauth` | Runs `openssl s_client` from inside the OAuth pod to verify TLS connectivity and the negotiated cipher suite |
| `_clean_user_identities` | Deletes lab User and Identity objects without touching `developer` or `kubeadmin` |
| `demo_check_keycloak` | Idempotently ensures Keycloak has both LDAP federations and the `openshift` OIDC client. Keycloak uses `dev-file` DB so everything is lost on pod restart |

---

## Demo Step 1 — Reproduce the Failure

> Script function: `demo_paso1_fallo`

### bob_modern (TLS 1.3) — should work

```bash
oc login -u bob_modern -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected:

```
Login successful.
```

### bob_legacy (TLS 1.2 + RSA Kx) — should fail

```bash
oc login -u bob_legacy -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected — **this is the bug**:

```
Error from server (InternalError): Internal error occurred: unexpected response: 500
```

### OAuth server logs

```bash
oc login -u kubeadmin -p <password> https://api.crc.testing:6443 --insecure-skip-tls-verify
oc logs -n openshift-authentication deploy/oauth-openshift --tail=10 \
  | grep -i -E "legacy|error|EOF|Network"
```

Expected:

```
E0610 15:49:43.023059  1 basicauth.go:45] Error authenticating login "bob_legacy"
  with provider "ldap-legacy": LDAP Result Code 200 "Network Error": EOF
```

`Network Error: EOF` means the TLS handshake failed silently — Go 1.22+ offered no cipher suites that the server could accept.

### Check User and Identity objects

```bash
oc get users
oc get identities
```

Expected:

```
NAME         FULL NAME    IDENTITIES
bob_modern   Bob Modern   ldap-modern:Ym9iX21vZGVybg

NAME                         IDP NAME      USER NAME
ldap-modern:Ym9iX21vZGVybg   ldap-modern   bob_modern
```

`bob_legacy` doesn't appear — the login failed before OCP could create any objects.

---

## Demo Step 2 — Case B: TLS 1.3 (Reference)

> Script function: `demo_paso2_casoB`

This step shows that the modern server (TLS 1.3) works without issues. It serves as a reference for where TLS 1.3 solves the problem entirely.

```bash
# Verify TLS 1.3 protocol
oc exec -n legacy-auth deploy/openldap-modern -- \
  openssl s_client -connect localhost:636 2>/dev/null | grep "Protocol"

# bob_modern logs in
oc login -u bob_modern -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify

# Verify identity
oc login -u kubeadmin -p <password> https://api.crc.testing:6443 --insecure-skip-tls-verify
oc get identities | grep modern
```

---

## Demo Step 3 — Fix A: Enable ECDHE on the Legacy Server

> Script function: `demo_paso3_casoA`

The fix is straightforward: add `+ECDHE-RSA` and `+CURVE-ALL` to the GnuTLS priority string. The `+CURVE-ALL` part is easy to miss — without it, GnuTLS doesn't know which elliptic curves to use and ECDHE silently doesn't activate.

### Update the cipher suite

```bash
oc set env deploy/openldap-legacy -n legacy-auth \
  LDAP_TLS_CIPHER_SUITE='NONE:+VERS-TLS1.2:+ECDHE-RSA:+RSA:+AES-128-GCM:+AES-256-GCM:+AES-128-CBC:+AES-256-CBC:+MAC-ALL:+SIGN-ALL:+CTYPE-X509:+COMP-ALL:+CURVE-ALL'
```

### Restart with PVC cleanup

The `osixia/openldap` image has a safety check: if the config `emptyDir` is empty but the data PVC has content, slapd refuses to start ("config directory is empty but not the database directory"). The script handles this automatically via `_ldap_cleanup_and_restart`:

```bash
oc scale deploy/openldap-legacy -n legacy-auth --replicas=0

# Clean the PVC with a temporary pod
oc run ldap-cleanup -n legacy-auth --image=osixia/openldap:1.2.5 \
  --restart=Never --rm -i \
  --overrides='{
    "spec": {
      "containers": [{
        "name": "ldap-cleanup",
        "image": "osixia/openldap:1.2.5",
        "command": ["sh", "-c", "rm -rf /var/lib/ldap/* && echo CLEANED"],
        "volumeMounts": [{"name": "data", "mountPath": "/var/lib/ldap"}],
        "securityContext": {"runAsUser": 0}
      }],
      "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "openldap-legacy-data"}}],
      "serviceAccountName": "openldap-legacy-sa"
    }
  }'

oc scale deploy/openldap-legacy -n legacy-auth --replicas=1
oc rollout status deploy/openldap-legacy -n legacy-auth --timeout=120s
```

After it comes back up, re-populate users and **recycle the OAuth pods** (the script does this via `_populate_legacy_users` and `_refresh_oauth`):

```bash
# Re-populate users (see Part 2)
# ...

# Force OAuth to establish fresh LDAP connections
oc delete pods -n openshift-authentication -l app=oauth-openshift
```

> **Why recycle OAuth?** Go's HTTP/TLS stack maintains persistent TCP connections. After an LDAP pod restart, the OAuth server still holds the old connection. Without recycling, you get `Network Error: EOF` or `LDAP Result Code 32 "No Such Object"` even though the LDAP server is working correctly with the new cipher suite.

### Confirm the cipher suite changed

```bash
oc exec -n legacy-auth deploy/openldap-legacy -c openldap -- \
  openssl s_client -connect localhost:636 -tls1_2 </dev/null 2>&1 \
  | grep "Cipher is"
```

Expected — **ECDHE is now active**:

```
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
```

### bob_legacy should now log in

The script uses a retry loop (up to 5 attempts) because the OAuth server may take a few seconds to establish a working connection to the restarted LDAP:

```bash
oc login -u bob_legacy -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected:

```
Login successful.
```

### Verify Identity objects

```bash
oc login -u kubeadmin -p <password> https://api.crc.testing:6443 --insecure-skip-tls-verify
oc get users
oc get identities
```

Expected:

```
NAME           FULL NAME      IDENTITIES
bob_legacy     Bob Legacy     ldap-legacy:Ym9iX2xlZ2FjeQ
bob_modern     Bob Modern     ldap-modern:Ym9iX21vZGVybg

NAME                           IDP NAME      USER NAME
ldap-legacy:Ym9iX2xlZ2FjeQ     ldap-legacy   bob_legacy
ldap-modern:Ym9iX21vZGVybg     ldap-modern   bob_modern
```

### Equivalent fix on Windows Active Directory

On a Windows Server Domain Controller, enable the ECDHE cipher suites via PowerShell:

```powershell
# Check what's currently enabled
Get-TlsCipherSuite | Where-Object { $_.Name -like "*ECDHE*RSA*" }

# Enable ECDHE suites if missing
Enable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
Enable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

# Verify
Get-TlsCipherSuite | Select-Object -First 10
```

---

## Demo Step 4 — Fix C: Keycloak as OIDC Broker

> Script function: `demo_paso4_casoC`

This step demonstrates the Keycloak workaround for when you **can't modify the Active Directory**. The script first reverts `openldap-legacy` to the broken RSA-only cipher suite, then shows:

1. OCP **cannot** authenticate directly against the legacy LDAP (same failure as Step 1)
2. Keycloak (Java) **can** authenticate the same user via its LDAP federation
3. The user can log into OCP through the `keycloak-broker` IDP in the web console

### Revert to broken cipher suite

```bash
oc set env deploy/openldap-legacy -n legacy-auth \
  LDAP_TLS_CIPHER_SUITE='NONE:+VERS-TLS1.2:+RSA:+AES-128-GCM:+AES-256-GCM:+AES-128-CBC:+AES-256-CBC:+MAC-ALL:+SIGN-ALL:+CTYPE-X509:+COMP-ALL'
```

Then PVC cleanup + restart + repopulate users + recycle OAuth (same procedure as Step 3, the script handles this automatically).

### Verify Keycloak can reach the LDAP

```bash
# Ensure federations exist (the script does this via demo_check_keycloak)
oc exec -n keycloak keycloak-0 -- bash -c '
  mkdir -p /tmp/kc
  /opt/keycloak/bin/kcadm.sh config credentials \
    --config /tmp/kc/cfg \
    --server http://localhost:8080 \
    --realm master \
    --user temp-admin \
    --password <KC_PASS> 2>/dev/null
  /opt/keycloak/bin/kcadm.sh get components \
    --config /tmp/kc/cfg -r master \
    -q type=org.keycloak.storage.UserStorageProvider \
    --fields name,providerId'
```

### Sync users from legacy LDAP to Keycloak

The script extracts the federation ID and triggers a full sync:

```bash
oc exec -n keycloak keycloak-0 -- bash -c '
  /opt/keycloak/bin/kcadm.sh config credentials \
    --config /tmp/kc/cfg \
    --server http://localhost:8080 \
    --realm master \
    --user temp-admin \
    --password <KC_PASS> 2>/dev/null

  LEGACY_ID=$(/opt/keycloak/bin/kcadm.sh get components \
    --config /tmp/kc/cfg -r master \
    -q type=org.keycloak.storage.UserStorageProvider \
    --fields id,name 2>/dev/null \
    | grep -B1 "ldap-legacy" | head -1 | tr -d " \"," | sed "s/id://")

  echo "Federation ID: $LEGACY_ID"
  /opt/keycloak/bin/kcadm.sh create \
    "user-storage/$LEGACY_ID/sync?action=triggerFullSync" \
    --config /tmp/kc/cfg -r master'
```

### Verify carol_legacy authenticates through Keycloak

```bash
oc exec -n keycloak keycloak-0 -- bash -c '
  /opt/keycloak/bin/kcadm.sh config credentials \
    --config /tmp/kc/test \
    --server http://localhost:8080 \
    --realm master \
    --user carol_legacy \
    --password "Password123!"'
```

Expected:

```
Logging into http://localhost:8080 as user carol_legacy of realm master
```

carol_legacy can authenticate even though the LDAP server only offers RSA Kx ciphers — because Keycloak's Java LDAP stack doesn't have Go's restriction.

### carol_legacy fails against OCP directly

```bash
oc login -u carol_legacy -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected — confirms OCP still can't talk to the broken LDAP:

```
Error from server (InternalError): Internal error occurred: unexpected response: 500
```

### Browser-based login via keycloak-broker

At this point the script pauses and asks you to open the browser:

1. Navigate to `https://console-openshift-console.apps-crc.testing`
2. Select the **keycloak-broker** identity provider
3. Log in as `carol_legacy` / `Password123!`

The flow: Browser → OCP Console → OAuth → Keycloak (OIDC standard flow) → Keycloak LDAP federation (port 389, no TLS issue) → Success.

### Verify Identity objects

```bash
oc login -u kubeadmin -p <password> https://api.crc.testing:6443 --insecure-skip-tls-verify
oc get users
oc get identities | grep -E "NAME|carol|keycloak"
```

Expected:

```
NAME           IDENTITIES
carol_legacy   keycloak-broker:48ead577-6e98-40b4-af50-8a644880bead

NAME                                                   IDP NAME
keycloak-broker:48ead577-6e98-40b4-af50-8a644880bead   keycloak-broker
```

The Identity shows `keycloak-broker` — not `ldap-legacy`. The AD was never touched.

---

## Results Summary

> Script function: `demo_resumen`

### Before the fix (RSA Kx only)

| User | IDP | TLS | Result | Error |
|---|---|---|---|---|
| bob_modern | ldap-modern | TLS 1.3 | **OK** | — |
| bob_legacy | ldap-legacy | TLS 1.2 RSA Kx | **FAIL** | Network Error: EOF |

### After Fix A (ECDHE enabled)

| User | IDP | TLS | Cipher | Result |
|---|---|---|---|---|
| bob_legacy | ldap-legacy | TLS 1.2 | ECDHE-RSA-AES256-GCM-SHA384 | **OK** |

### After Fix C (Keycloak broker, LDAP reverted to RSA-only)

| User | IDP | Flow | Result |
|---|---|---|---|
| carol_legacy | keycloak-broker | OCP → Keycloak → LDAP(389) | **OK** |
| carol_legacy | ldap-legacy (direct) | OCP → LDAP(636) | **FAIL** |

---

## Root Cause

### Go 1.22 changelog (crypto/tls)

> _The RSA key exchange cipher suites have been removed from the default list._

The dropped cipher suites:

| IANA Name | GnuTLS token | Go 1.21 | Go 1.22+ |
|---|---|---|---|
| TLS_RSA_WITH_AES_128_GCM_SHA256 | +RSA:+AES-128-GCM | Supported | **Dropped** |
| TLS_RSA_WITH_AES_256_GCM_SHA384 | +RSA:+AES-256-GCM | Supported | **Dropped** |
| TLS_RSA_WITH_AES_128_CBC_SHA256 | +RSA:+AES-128-CBC | Supported | **Dropped** |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | +ECDHE-RSA:+AES-128-GCM | Supported | **Still supported** |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | +ECDHE-RSA:+AES-256-GCM | Supported | **Still supported** |

The reason for the removal: RSA Key Exchange has no Perfect Forward Secrecy. If someone records encrypted traffic today and later obtains the server's private key, they can decrypt everything retroactively. ECDHE doesn't have this problem — each session generates a fresh key pair.

### Affected OpenShift versions

| OCP Version | Go | RSA Kx | Affected |
|---|---|---|---|
| 4.13 | Go 1.20 | Supported | No |
| 4.14 | Go 1.21 | Supported | **No** — Go 1.21 still includes RSA Kx by default |
| **4.15** | **Go 1.22** | **Dropped** | **Yes** — first affected version |
| 4.16+ | Go 1.22+ | **Dropped** | **Yes** |

If a customer is on OCP 4.14 and LDAP authentication works, the problem will surface when they upgrade to 4.15+.

---

## Known Issues and Workarounds

### osixia/openldap PVC cleanup

The `osixia/openldap:1.2.5` image has a safety check on startup: if the config directory (`emptyDir`, empty on every pod start) is empty but the data directory (PVC) has content from a previous run, slapd refuses to start with "config directory is empty but not the database directory". During the demo, the cipher suite changes via `oc set env` trigger a new rollout, and the new pod inherits the old PVC data.

The script handles this by scaling down, running a cleanup pod to wipe `/var/lib/ldap/*`, then scaling back up. This forces `osixia/openldap` to re-initialize from scratch.

### OAuth connection caching

Go's `crypto/tls` maintains persistent TCP connections. After an LDAP pod restarts (new IP, new TLS session), the OAuth server may still hold stale connections from the old pod. Symptoms: `Network Error: EOF` or `LDAP Result Code 32 "No Such Object"` even though the LDAP server is working correctly.

The script fixes this by deleting the OAuth pods (`_refresh_oauth`), forcing them to establish fresh connections.

### DH parameter generation

The `osixia/openldap` image generates Diffie-Hellman parameters on first TLS initialization. Under CRC/emulation this can take 2-3 minutes. During this time the pod is `Running` but port 636 doesn't respond. The script polls with `openssl s_client` until the TLS handshake succeeds (`_wait_for_slapd_tls`).

### Keycloak dev-file DB

The lab uses `db.vendor: dev-file` for simplicity. This is an in-memory/file database that's **lost when the pod restarts**. The script's `demo_check_keycloak` function handles this by checking for and recreating:
- Both LDAP federations (ldap-legacy, ldap-modern)
- The `openshift` OIDC client with `directAccessGrantsEnabled=true`

---

## Recommendations

| Option | Complexity | Requires AD changes | Lab validated |
|---|---|---|---|
| **A** — Enable ECDHE in AD | Low | Yes | **Yes** |
| **B** — Migrate AD to TLS 1.3 | Medium | Yes | **Yes** (openldap-modern) |
| **C** — RHBK as OIDC broker | Medium-High | **No** | **Yes** |

**Option A is the recommended starting point.** It's the least invasive change — no new components, just a cipher suite configuration update on the AD side. On Windows Server, `Enable-TlsCipherSuite` is a one-liner.

**Option C is the fallback when the AD can't be touched** — common in organizations where the AD team and the platform team don't move at the same speed. Deploying RHBK adds a component to maintain, but it also opens the door to more sophisticated authentication flows (MFA, social login, attribute mapping) that can be valuable beyond just solving this specific problem.

---

_Lab built: June 2026 — OpenShift CRC 4.21 — api.crc.testing:6443_
