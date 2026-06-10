# Lab: LDAP Authentication with Legacy TLS on OpenShift 4.15+

## Background

This lab reproduces a real-world issue where an **Active Directory using TLS 1.2 with RSA Key Exchange cipher suites** stops working after upgrading to OpenShift 4.15+. The root cause is that Go 1.22 — which ships with OCP 4.15 — silently dropped support for `TLS_RSA_WITH_*` cipher suites ([Go 1.22 changelog](https://go.dev/doc/go1.22#crypto/tls)).

The symptom is deceptively simple: users who were logging in just fine suddenly can't authenticate after an OCP upgrade. The OAuth server logs show `Network Error: EOF` — a TLS handshake failure that looks like a network problem but is actually a cipher suite incompatibility.

### What this lab demonstrates

| Scenario | TLS | Cipher | OCP OAuth (Go 1.22+) | Keycloak (Java) |
|----------|-----|--------|----------------------|-----------------|
| Legacy LDAP — RSA Kx only | TLS 1.2 | `TLS_RSA_WITH_AES_256_GCM_SHA384` | **FAILS** — `Network Error: EOF` | Works fine |
| Legacy LDAP — with ECDHE fix | TLS 1.2 | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | **Works** | Works fine |
| Modern LDAP — TLS 1.3 | TLS 1.3 | ECDHE only | **Works** | Works fine |

The key insight: Keycloak uses Java's LDAP stack, which doesn't have Go's restriction, so the same broken LDAP server works fine when accessed through Keycloak. This opens up a useful workaround path when you can't touch the AD.

### Solutions covered

- **Option A** — Enable ECDHE cipher suites on the LDAP/AD server → **Validated ✓**
- **Option B** — Migrate to TLS 1.3 → **Validated ✓** (via openldap-modern)
- **Option C** — Put Keycloak/RHBK in front as an OIDC broker → **Validated ✓**

---

## Prerequisites

- OpenShift CRC 4.15+ (this lab was built on CRC 4.21 — note that OCP 4.14 is **not** affected)
- `oc` CLI installed and configured
- cluster-admin access

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

A note on certificate requirements: the server certificates **must** include `keyEncipherment` in the Key Usage extension. Without it, RSA key exchange cipher suites fail at the TLS handshake level regardless of what the server advertises. This is a common gotcha when generating certs manually.

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
oc exec -n legacy-auth deploy/openldap-legacy -- \
  ldapadd -x -H ldap://localhost:389 \
  -D "cn=admin,dc=legacy,dc=local" -w "AdminPass123!" <<'EOF'
dn: ou=users,dc=legacy,dc=local
objectClass: organizationalUnit
ou: users

dn: uid=bob_legacy,ou=users,dc=legacy,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
uid: bob_legacy
cn: Bob Legacy
sn: Legacy
mail: bob@legacy.local
userPassword: Password123!

dn: uid=carol_legacy,ou=users,dc=legacy,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
uid: carol_legacy
cn: Carol Legacy
sn: Legacy
mail: carol@legacy.local
userPassword: Password123!
EOF
```

### Verify

```bash
oc exec -n legacy-auth deploy/openldap-legacy -- \
  ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=legacy,dc=local" -w "AdminPass123!" \
  -b "ou=users,dc=legacy,dc=local" uid cn
```

Expected output:

```
# bob_legacy, users, legacy.local
dn: uid=bob_legacy,ou=users,dc=legacy,dc=local
uid: bob_legacy
cn: Bob Legacy

# carol_legacy, users, legacy.local
dn: uid=carol_legacy,ou=users,dc=legacy,dc=local
uid: carol_legacy
cn: Carol Legacy
```

### Confirm the cipher suite

```bash
oc exec -n legacy-auth deploy/openldap-legacy -- \
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
NAME              IMAGE REPOSITORY                                                                TAGS     UPDATED
openldap-modern   image-registry.openshift-image-registry.svc:5000/legacy-auth/openldap-modern   latest   <timestamp>
```

> **⚠ Troubleshooting: `unknown database type "mdb"`**
>
> If the pod logs show:
> ```
> slaptest: bad configuration file!
> /tmp/slapd.conf: line XX: unknown database type "mdb"
> ```
> The `moduleload back_mdb` line is missing from the entrypoint's `slapd.conf`. In OpenLDAP 2.4.x (osixia) the MDB backend is statically compiled in, but in **2.5.x (Debian Bookworm) it's a loadable module** that must be explicitly declared.

> **⚠ Troubleshooting: TLS init failed with `-u openldap`**
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

## Part 5 — Reproduce the Failure

### 5.1 bob_modern (TLS 1.3) — should work

```bash
oc login -u bob_modern -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected:

```
Login successful.
```

### 5.2 bob_legacy (TLS 1.2 + RSA Kx) — should fail

```bash
oc login -u bob_legacy -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected — **this is the bug**:

```
Error from server (InternalError): Internal error occurred: unexpected response: 500
```

### 5.3 See the actual error in the OAuth server logs

```bash
oc login -u kubeadmin -p <password> https://api.crc.testing:6443 --insecure-skip-tls-verify
oc logs -n openshift-authentication deploy/oauth-openshift --tail=5
```

Expected:

```
E0610 15:49:43.023059  1 basicauth.go:45] Error authenticating login "bob_legacy"
  with provider "ldap-legacy": LDAP Result Code 200 "Network Error": EOF
```

`Network Error: EOF` means the TLS handshake failed silently — Go 1.22+ offered no cipher suites that the server could accept.

### 5.4 Check User and Identity objects

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

## Part 6 — Fix A: Enable ECDHE on the Legacy LDAP

The fix is straightforward: add `+ECDHE-RSA` and `+CURVE-ALL` to the GnuTLS priority string. The `+CURVE-ALL` part is easy to miss — without it, GnuTLS doesn't know which elliptic curves to use and ECDHE silently doesn't activate.

### 6.1 Update the cipher suite

```bash
oc set env deploy/openldap-legacy -n legacy-auth \
  LDAP_TLS_CIPHER_SUITE='NONE:+VERS-TLS1.2:+ECDHE-RSA:+RSA:+AES-128-GCM:+AES-256-GCM:+AES-128-CBC:+AES-256-CBC:+MAC-ALL:+SIGN-ALL:+CTYPE-X509:+COMP-ALL:+CURVE-ALL'
```

> If the pod fails after the rollout with "config directory is empty but not the database directory", the PVC needs to be cleaned before it can reinitialize:

```bash
oc scale deploy/openldap-legacy -n legacy-auth --replicas=0
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
```

After it comes back up, re-run the user population step from Part 2.

### 6.2 Confirm the cipher suite changed

```bash
oc exec -n legacy-auth deploy/openldap-legacy -- \
  openssl s_client -connect localhost:636 -tls1_2 </dev/null 2>&1 \
  | grep "Cipher is"
```

Expected — **ECDHE is now active**:

```
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
```

### 6.3 bob_legacy should now log in

```bash
oc login -u bob_legacy -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected:

```
Login successful.
```

### 6.4 Verify Identity objects

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

## Part 7 — Fix C: Keycloak as OIDC Broker

This option doesn't require any changes to the Active Directory. Keycloak uses Java's LDAP client stack, which still supports RSA Key Exchange cipher suites — so it can talk to the broken LDAP server without issues. OCP then authenticates against Keycloak via OIDC, bypassing the Go TLS restriction entirely.

### 7.1 Install RHBK

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

### 7.2 Deploy a Keycloak instance

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

### 7.3 Get admin credentials

```bash
oc get secret keycloak-initial-admin -n keycloak \
  -o go-template='{{.data.username | base64decode}} / {{.data.password | base64decode}}'
```

### 7.4 A note on the Keycloak 26 admin console

> Keycloak 26 includes a third-party cookie check in the admin console. On first load, it renders a hidden iframe pointing to `/realms/master/protocol/openid-connect/3p-cookies/step1.html` and waits for a postMessage response. If your browser blocks third-party cookies — which most modern browsers do by default, and corporate-managed Chrome tends to enforce strictly — this check times out and you see a `somethingWentWrong` error before you even get to the login form.
>
> The most reliable workaround is to skip the UI entirely and do everything through `kcadm.sh` via `oc exec`. The pattern is:
>
> ```bash
> oc exec -n keycloak keycloak-0 -- bash -c "\
> mkdir -p /tmp/kc &&\
> /opt/keycloak/bin/kcadm.sh config credentials \
>   --config /tmp/kc/cfg \
>   --server http://localhost:8080 \
>   --realm master \
>   --user <admin_user> \
>   --password <admin_pass> &&\
> /opt/keycloak/bin/kcadm.sh <operation> --config /tmp/kc/cfg ..."
> ```
>
> This connects to Keycloak's loopback interface — no TLS, no cookies, no browser involved. It's also how you'd automate Keycloak configuration in a GitOps pipeline, so it's good practice anyway.
>
> If you do need the UI, the options are: run Keycloak with `--spi-login-protocol-openid-connect-legacy-logout-redirect-uri=true`, or configure `SameSite=None; Secure` on the Route (requires proper HTTPS).

### 7.5 Configure LDAP federation

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
  -s 'config.userObjectClasses=[\"inetOrgPerson, organizationalPerson\"]' \
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
  -s 'config.userObjectClasses=[\"inetOrgPerson, organizationalPerson\"]' \
  -s 'config.editMode=[\"READ_ONLY\"]' \
  -s 'config.authType=[\"simple\"]' \
  -s 'config.enabled=[\"true\"]'"
```

> **Note**: Keycloak connects to LDAP on **port 389 (plaintext)** here, not LDAPS. Pod-to-pod traffic inside the cluster travels over the SDN and doesn't leave the node unencrypted. More importantly, it completely sidesteps the TLS cipher suite issue — which is exactly the point of this workaround.

### 7.6 Sync and verify users

```bash
oc exec -n keycloak keycloak-0 -- bash -c "\
mkdir -p /tmp/kc &&\
/opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kc/cfg \
  --server http://localhost:8080 \
  --realm master \
  --user $KC_ADMIN \
  --password $KC_PASS &&\

LEGACY_ID=\$(/opt/keycloak/bin/kcadm.sh get components \
  --config /tmp/kc/cfg -r master \
  -q type=org.keycloak.storage.UserStorageProvider \
  --fields id,name 2>/dev/null | \
  grep -B1 ldap-legacy | grep id | \
  sed 's/.*: \"//;s/\".*//' ) &&\
echo \"Federation ID: \$LEGACY_ID\" &&\

/opt/keycloak/bin/kcadm.sh create \
  \"user-storage/\$LEGACY_ID/sync?action=triggerFullSync\" \
  --config /tmp/kc/cfg -r master &&\
echo 'Sync complete' &&\

/opt/keycloak/bin/kcadm.sh get 'users?username=carol_legacy&exact=true' \
  --config /tmp/kc/cfg -r master \
  --fields username,federationLink"
```

Expected output:

```
Federation ID: 5-QaBqtPTiygzW7LFHsThw
Sync complete
[ {
  "username" : "carol_legacy",
  "federationLink" : "5-QaBqtPTiygzW7LFHsThw"
} ]
```

### 7.7 Verify carol_legacy can authenticate through Keycloak

```bash
oc exec -n keycloak keycloak-0 -- bash -c "\
/opt/keycloak/bin/kcadm.sh config credentials \
  --config /tmp/kc/test \
  --server http://localhost:8080 \
  --realm master \
  --user carol_legacy \
  --password 'Password123!'"
```

Expected:

```
Logging into http://localhost:8080 as user carol_legacy of realm master
```

carol_legacy can authenticate even though the LDAP server only offers RSA Kx ciphers — because Keycloak's Java LDAP stack doesn't have Go's restriction.

### 7.8 Create an OIDC client for OCP

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

### 7.9 Add Keycloak as an OIDC identity provider in OCP

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

### 7.10 Test login through Keycloak

```bash
oc login -u carol_legacy -p 'Password123!' \
  https://api.crc.testing:6443 --insecure-skip-tls-verify
```

Expected:

```
Login successful.
```

```bash
oc login -u kubeadmin -p <password> https://api.crc.testing:6443 --insecure-skip-tls-verify
oc get users
oc get identities
```

Expected:

```
NAME           IDENTITIES
carol_legacy   keycloak-broker:48ead577-6e98-40b4-af50-8a644880bead

NAME                                                   IDP NAME
keycloak-broker:48ead577-6e98-40b4-af50-8a644880bead   keycloak-broker
```

The full flow: `oc login` → OCP OAuth → Keycloak (OIDC Resource Owner Password grant) → Keycloak federates carol_legacy from the legacy LDAP (port 389) → success.

---

## Part 8 — Results Summary

### Before the fix (RSA Kx only)

| User | IDP | TLS | Result | Error |
|------|-----|-----|--------|-------|
| bob_modern | ldap-modern | TLS 1.3 | **OK** | — |
| bob_legacy | ldap-legacy | TLS 1.2 RSA Kx | **FAIL** | `Network Error: EOF` |

### After Fix A (ECDHE enabled)

| User | IDP | TLS | Cipher | Result |
|------|-----|-----|--------|--------|
| bob_legacy | ldap-legacy | TLS 1.2 | `ECDHE-RSA-AES256-GCM-SHA384` | **OK** |
| carol_legacy | ldap-legacy | TLS 1.2 | `ECDHE-RSA-AES256-GCM-SHA384` | **OK** |

### After Fix C (Keycloak broker)

| User | IDP | Flow | Result |
|------|-----|------|--------|
| bob_legacy | keycloak-broker | OCP → Keycloak → LDAP(389) | **OK** |
| carol_legacy | keycloak-broker | OCP → Keycloak → LDAP(389) | **OK** |

---

## Root Cause

### Go 1.22 changelog (crypto/tls)

> *The RSA key exchange cipher suites have been removed from the default list.*

The dropped cipher suites:

| IANA Name | GnuTLS token | Go 1.21 | Go 1.22+ |
|-----------|-------------|---------|----------|
| `TLS_RSA_WITH_AES_128_GCM_SHA256` | `+RSA:+AES-128-GCM` | Supported | **Dropped** |
| `TLS_RSA_WITH_AES_256_GCM_SHA384` | `+RSA:+AES-256-GCM` | Supported | **Dropped** |
| `TLS_RSA_WITH_AES_128_CBC_SHA256` | `+RSA:+AES-128-CBC` | Supported | **Dropped** |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `+ECDHE-RSA:+AES-128-GCM` | Supported | **Still supported** |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `+ECDHE-RSA:+AES-256-GCM` | Supported | **Still supported** |

The reason for the removal: RSA Key Exchange has no Perfect Forward Secrecy. If someone records encrypted traffic today and later obtains the server's private key, they can decrypt everything retroactively. ECDHE doesn't have this problem — each session generates a fresh key pair.

### Affected OpenShift versions

| OCP Version | Go | RSA Kx | Affected |
|-------------|-----|--------|----------|
| 4.13 | Go 1.20 | Supported | No |
| 4.14 | Go 1.21 | Supported | **No** — Go 1.21 still includes RSA Kx by default |
| **4.15** | **Go 1.22** | **Dropped** | **Yes** — first affected version |
| 4.16+ | Go 1.22+ | **Dropped** | **Yes** |

If a customer is on OCP 4.14 and LDAP authentication works, the problem will surface when they upgrade to 4.15+.

---

## Recommendations

| Option | Complexity | Requires AD changes | Lab validated |
|--------|-----------|---------------------|---------------|
| **A** — Enable ECDHE in AD | Low | Yes | **Yes** |
| **B** — Migrate AD to TLS 1.3 | Medium | Yes | **Yes** (openldap-modern) |
| **C** — RHBK as OIDC broker | Medium-High | **No** | **Yes** |

**Option A is the recommended starting point.** It's the least invasive change — no new components, just a cipher suite configuration update on the AD side. On Windows Server, `Enable-TlsCipherSuite` is a one-liner.

**Option C is the fallback when the AD can't be touched** — common in organizations where the AD team and the platform team don't move at the same speed. Deploying RHBK adds a component to maintain, but it also opens the door to more sophisticated authentication flows (MFA, social login, attribute mapping) that can be valuable beyond just solving this specific problem.

---

*Lab built: June 2026 — OpenShift CRC 4.21 — api.crc.testing:6443*
