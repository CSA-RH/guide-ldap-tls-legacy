#!/bin/bash
# =============================================================================
#  DEMO: LDAP TLS Legacy + OpenShift OAuth
#  Principado de Asturias — Caso de uso real
#
#  Ejecutar como: source demo-script.sh
#  O copiar/pegar cada bloque manualmente
# =============================================================================

# CREDENCIALES — ajustar antes de la demo
OCP_API="https://api.crc.testing:6443"
KUBEADMIN_PASS="H5r8u-U2gIe-INVpJ-UME4Q"
KC_PASS="af9af5741acf4b9dbc0b880d94b7d2ea"

# =============================================================================
#  HELPERS — funciones reutilizables
# =============================================================================

_ldap_cleanup_and_restart() {
  # Limpia PVC + reinicia openldap-legacy con el cipher suite actual.
  # Necesario porque osixia/openldap no arranca si emptyDir config está
  # vacío pero PVC data tiene contenido de una ejecución anterior.
  local cipher_desc="${1:-cipher suite actual}"

  echo ">>> [Lab artefact] Limpiando PVC de openldap-legacy ($cipher_desc)..."
  oc scale deploy/openldap-legacy -n legacy-auth --replicas=0 2>/dev/null
  oc delete pod ldap-cleanup -n legacy-auth --ignore-not-found 2>/dev/null
  sleep 2

  cat << 'PODSPEC' | oc apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ldap-cleanup
  namespace: legacy-auth
spec:
  serviceAccountName: openldap-legacy-sa
  restartPolicy: Never
  containers:
  - name: ldap-cleanup
    image: osixia/openldap:1.2.5
    command: ["sh", "-c", "rm -rf /var/lib/ldap/* && echo CLEANED"]
    securityContext:
      runAsUser: 0
    volumeMounts:
    - name: data
      mountPath: /var/lib/ldap
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: openldap-legacy-data
PODSPEC

  for i in $(seq 1 20); do
    STATUS=$(oc get pod ldap-cleanup -n legacy-auth -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$STATUS" = "Succeeded" ] && break
    [ "$STATUS" = "Failed" ] && echo "ERROR: cleanup pod failed" && break
    sleep 3
  done
  oc logs pod/ldap-cleanup -n legacy-auth 2>/dev/null || true
  oc delete pod ldap-cleanup -n legacy-auth --ignore-not-found 2>/dev/null

  echo ">>> Arrancando openldap-legacy..."
  oc scale deploy/openldap-legacy -n legacy-auth --replicas=1
  oc rollout status deploy/openldap-legacy -n legacy-auth --timeout=120s
}

_wait_for_slapd_tls() {
  local pod
  pod=$(oc get pod -n legacy-auth -l app=openldap-legacy \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

  echo ">>> Esperando a que slapd inicialice TLS (DH params + certs)..."
  for i in $(seq 1 60); do
    # Comprobar primero que el pod tiene el contenedor listo
    local ready
    ready=$(oc get pod -n legacy-auth "$pod" \
      -o jsonpath='{.status.containerStatuses[?(@.name=="openldap")].ready}' 2>/dev/null)
    if [ "$ready" != "true" ]; then
      printf "    [%02d/60] contenedor openldap arrancando...\r" "$i"
      sleep 5
      continue
    fi

    # Intentar una conexión LDAPS (sin depender de ldapsearch)
    if oc exec -n legacy-auth "$pod" -c openldap -- \
      bash -c 'echo Q | openssl s_client -connect localhost:636 2>/dev/null | grep -q "CONNECTED"' \
      2>/dev/null; then
      echo "    slapd TLS listo (intento $i)                    "
      return 0
    fi
    printf "    [%02d/60] esperando TLS...\r" "$i"
    sleep 5
  done
  echo ""
  echo "ERROR: slapd no respondió en 5 minutos"
  return 1
}

_populate_legacy_users() {
  # Crea la OU y los usuarios de test en openldap-legacy.
  local pod
  pod=$(oc get pod -n legacy-auth -l app=openldap-legacy -o jsonpath='{.items[0].metadata.name}')

  echo ">>> Poblando usuarios legacy..."
  oc exec -n legacy-auth "$pod" -c openldap -- bash -c 'cat > /tmp/users.ldif << LDIF
dn: ou=users,dc=legacy,dc=local
objectClass: organizationalUnit
ou: users

dn: uid=bob_legacy,ou=users,dc=legacy,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: bob_legacy
sn: Legacy
givenName: Bob
cn: Bob Legacy
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
sn: Legacy
givenName: Carol
cn: Carol Legacy
uidNumber: 10002
gidNumber: 10002
homeDirectory: /home/carol_legacy
loginShell: /bin/bash
mail: carol_legacy@legacy.local
userPassword: Password123!
LDIF'

  oc exec -n legacy-auth "$pod" -c openldap -- ldapadd -x \
    -H ldap://localhost \
    -D "cn=admin,dc=legacy,dc=local" \
    -w AdminPass123! \
    -f /tmp/users.ldif 2>&1 || true

  echo ">>> Verificando usuarios en el directorio..."
  for i in $(seq 1 15); do
    local result
    result=$(oc exec -n legacy-auth "$pod" -c openldap -- ldapsearch -x \
      -H ldap://localhost \
      -D "cn=admin,dc=legacy,dc=local" \
      -w AdminPass123! \
      -b "ou=users,dc=legacy,dc=local" "(uid=bob_legacy)" uid 2>/dev/null \
      | grep -c "uid: bob_legacy" || true)
    if [ "${result:-0}" -gt 0 ]; then
      echo "    Usuarios OK"
      return 0
    fi
    echo "    Esperando indexación... intento $i"
    sleep 3
  done
  echo "ERROR: usuarios no accesibles"
  return 1
}

_refresh_oauth() {
  # Fuerza reciclado de los pods del OAuth server para que establezcan
  # conexiones LDAP frescas. Go mantiene conexiones TCP persistentes;
  # sin este paso, el OAuth reutiliza conexiones muertas del pod anterior
  # y obtiene "Network Error: EOF" o "No Such Object" intermitentemente.
  echo ">>> Reciclando OAuth server (conexiones LDAP frescas)..."
  oc delete pods -n openshift-authentication -l app=oauth-openshift 2>/dev/null
  echo "    Esperando nuevo pod..."
  for i in $(seq 1 30); do
    READY=$(oc get pods -n openshift-authentication -l app=oauth-openshift \
      -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
    if [ "$READY" = "True" ]; then
      echo "    OAuth server listo (intento $i)"
      return 0
    fi
    sleep 5
  done
  echo "    WARN: OAuth server tardando más de lo esperado, continuando..."
}

_verify_ldap_from_oauth() {
  # Verifica que el OAuth server puede alcanzar el LDAP via TLS.
  local oauth_pod
  oauth_pod=$(oc get pods -n openshift-authentication -l app=oauth-openshift \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

  echo ">>> Verificando conectividad TLS desde OAuth server..."
  local cipher
  cipher=$(oc exec -n openshift-authentication "$oauth_pod" -- \
    bash -c 'echo Q | openssl s_client -connect openldap-legacy.legacy-auth.svc.cluster.local:636 2>&1 | grep "Cipher is"' 2>/dev/null)

  if [ -n "$cipher" ]; then
    echo "    $cipher"
    return 0
  else
    echo "    WARN: no se pudo verificar TLS desde OAuth pod"
    return 1
  fi
}

_clean_user_identities() {
  # Limpia objetos User e Identity del lab (no toca developer/kubeadmin)
  echo ">>> Limpiando User/Identity del lab..."
  oc delete user bob_legacy carol_legacy bob_modern carol_modern 2>/dev/null || true
  oc get identities -o name 2>/dev/null | grep -E "ldap-legacy|ldap-modern|keycloak-broker" \
    | xargs -I{} oc delete {} 2>/dev/null || true
}

# =============================================================================
#  PRE-DEMO — ejecutar ANTES de que llegue el cliente
#  Deja el entorno en estado "roto" listo para mostrar
# =============================================================================

pre_demo() {
  echo ">>> Preparando entorno para la demo..."

  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify

  # Asegura cipher suite roto (solo RSA Kx, sin ECDHE)
  echo ">>> Configurando cipher suite RSA-only (roto para Go 1.22+)..."
  oc set env deploy/openldap-legacy -n legacy-auth \
    LDAP_TLS_CIPHER_SUITE='NONE:+VERS-TLS1.2:+RSA:+AES-128-GCM:+AES-256-GCM:+AES-128-CBC:+AES-256-CBC:+MAC-ALL:+SIGN-ALL:+CTYPE-X509:+COMP-ALL'

  _ldap_cleanup_and_restart "solo RSA Kx — estado roto"
  _wait_for_slapd_tls
  _populate_legacy_users
  _refresh_oauth

  # Limpia objetos User/Identity del lab
  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify
  _clean_user_identities

  demo_check_keycloak

  echo ""
  echo ">>> Entorno listo. Estado:"
  echo "    openldap-legacy: TLS 1.2, solo RSA Kx (ROTO para OCP)"
  echo "    openldap-modern: TLS 1.3 (OK)"
  echo "    Usuarios legacy: bob_legacy / carol_legacy"
  echo "    Usuarios modern: bob_modern / carol_modern"
  echo "    Password todos: Password123!"
}


# =============================================================================
#  HELPER — Verificar y recrear federaciones Keycloak si no existen
# =============================================================================

demo_check_keycloak() {
  echo ">>> Verificando configuración Keycloak..."

  # Autenticar una vez y reutilizar la sesión para todas las operaciones
  oc exec -n keycloak keycloak-0 -- bash -c '
    mkdir -p /tmp/kc
    /opt/keycloak/bin/kcadm.sh config credentials \
      --config /tmp/kc/cfg \
      --server http://localhost:8080 \
      --realm master \
      --user temp-admin \
      --password '"$KC_PASS"'' 2>/dev/null

  # --- Verificar/crear federaciones LDAP ---
  local fed_json
  fed_json=$(oc exec -n keycloak keycloak-0 -- \
    /opt/keycloak/bin/kcadm.sh get components \
      --config /tmp/kc/cfg -r master \
      -q type=org.keycloak.storage.UserStorageProvider \
      --fields name 2>/dev/null)

  local fed_count
  fed_count=$(echo "$fed_json" | grep -c '"name"' 2>/dev/null || true)

  if [ "${fed_count:-0}" -lt 2 ]; then
    echo ">>> Federaciones no encontradas ($fed_count) — creando..."
    oc exec -n keycloak keycloak-0 -- bash -c '
      /opt/keycloak/bin/kcadm.sh create components \
        --config /tmp/kc/cfg -r master \
        -s name=ldap-legacy \
        -s providerId=ldap \
        -s providerType=org.keycloak.storage.UserStorageProvider \
        -s "config.vendor=[\"other\"]" \
        -s "config.connectionUrl=[\"ldap://openldap-legacy.legacy-auth.svc.cluster.local:389\"]" \
        -s "config.bindDn=[\"cn=admin,dc=legacy,dc=local\"]" \
        -s "config.bindCredential=[\"AdminPass123!\"]" \
        -s "config.usersDn=[\"ou=users,dc=legacy,dc=local\"]" \
        -s "config.usernameLDAPAttribute=[\"uid\"]" \
        -s "config.rdnLDAPAttribute=[\"uid\"]" \
        -s "config.uuidLDAPAttribute=[\"entryUUID\"]" \
        -s "config.userObjectClasses=[\"inetOrgPerson\"]" \
        -s "config.searchScope=[\"1\"]" \
        -s "config.authType=[\"simple\"]" \
        -s "config.editMode=[\"READ_ONLY\"]" \
        -s "config.enabled=[\"true\"]"

      /opt/keycloak/bin/kcadm.sh create components \
        --config /tmp/kc/cfg -r master \
        -s name=ldap-modern \
        -s providerId=ldap \
        -s providerType=org.keycloak.storage.UserStorageProvider \
        -s "config.vendor=[\"other\"]" \
        -s "config.connectionUrl=[\"ldap://openldap-modern.legacy-auth.svc.cluster.local:389\"]" \
        -s "config.bindDn=[\"cn=admin,dc=modern,dc=local\"]" \
        -s "config.bindCredential=[\"AdminPass123!\"]" \
        -s "config.usersDn=[\"ou=users,dc=modern,dc=local\"]" \
        -s "config.usernameLDAPAttribute=[\"uid\"]" \
        -s "config.rdnLDAPAttribute=[\"uid\"]" \
        -s "config.uuidLDAPAttribute=[\"entryUUID\"]" \
        -s "config.userObjectClasses=[\"inetOrgPerson\"]" \
        -s "config.searchScope=[\"1\"]" \
        -s "config.authType=[\"simple\"]" \
        -s "config.editMode=[\"READ_ONLY\"]" \
        -s "config.enabled=[\"true\"]"'
    echo ">>> Federaciones creadas OK"
  else
    echo ">>> Federaciones OK ($fed_count encontradas)"
  fi

  # --- Verificar/crear client OIDC para OCP ---
  local client_json
  client_json=$(oc exec -n keycloak keycloak-0 -- \
    /opt/keycloak/bin/kcadm.sh get clients \
      --config /tmp/kc/cfg -r master \
      --fields clientId -q clientId=openshift 2>/dev/null)

  local client_count
  client_count=$(echo "$client_json" | grep -c '"clientId"' 2>/dev/null || true)

  if [ "${client_count:-0}" -lt 1 ]; then
    echo ">>> Client OIDC 'openshift' no encontrado — creando..."
    oc exec -n keycloak keycloak-0 -- bash -c '
      /opt/keycloak/bin/kcadm.sh create clients \
        --config /tmp/kc/cfg -r master \
        -s clientId=openshift \
        -s protocol=openid-connect \
        -s enabled=true \
        -s clientAuthenticatorType=client-secret \
        -s secret=ocp-keycloak-secret-2026 \
        -s "redirectUris=[\"https://oauth-openshift.apps-crc.testing/oauth2callback/keycloak-broker\"]" \
        -s directAccessGrantsEnabled=true \
        -s standardFlowEnabled=true'
    echo ">>> Client OIDC creado OK"
  else
    echo ">>> Client OIDC OK"
  fi
}

# =============================================================================
#  PASO 1 — Mostrar el fallo
#  "Esto es lo que ve el cliente después de actualizar a OCP 4.15+"
# =============================================================================

demo_paso1_fallo() {
  echo ""
  echo "============================================"
  echo " PASO 1 — El fallo"
  echo "============================================"

  # bob_modern funciona (TLS 1.3 — referencia)
  echo ">>> bob_modern (TLS 1.3) — debe funcionar:"
  oc login -u bob_modern -p 'Password123!' $OCP_API --insecure-skip-tls-verify

  echo ""
  echo ">>> bob_legacy (TLS 1.2 + RSA Kx) — DEBE FALLAR:"
  oc login -u bob_legacy -p 'Password123!' $OCP_API --insecure-skip-tls-verify || true

  echo ""
  echo ">>> Error en los logs del OAuth server:"
  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify
  oc logs -n openshift-authentication deploy/oauth-openshift --tail=10 2>&1 \
    | grep -i -E "legacy|error|EOF|Network" | tail -3

  echo ""
  echo "============================================"
  echo " PAUSA — Muestra en la consola web:"
  echo " https://console-openshift-console.apps-crc.testing"
  echo " → User Management → Users     (bob_legacy NO aparece)"
  echo " → User Management → Identities (solo bob_modern)"
  echo " → Logs del OAuth: Network Error: EOF"
  echo ""
  echo " Puedes intentar login manual en la consola:"
  echo "   IDP: ldap-legacy  Usuario: bob_legacy  Password: Password123!"
  echo "   → Debe fallar"
  echo "============================================"
  echo "Pulsa ENTER para continuar..."
  read
}

# =============================================================================
#  PASO 2 — Caso B: TLS 1.3 como solución ideal
#  "Esto es adonde quieres llegar"
# =============================================================================

demo_paso2_casoB() {
  echo ""
  echo "============================================"
  echo " PASO 2 — Caso B: TLS 1.3"
  echo "============================================"

  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify

  echo ">>> Cipher suite del servidor moderno (TLS 1.3):"
  oc exec -n legacy-auth deploy/openldap-modern -- \
    openssl s_client -connect localhost:636 2>/dev/null | grep "Protocol"

  echo ""
  echo ">>> bob_modern se autentica sin problema:"
  oc login -u bob_modern -p 'Password123!' $OCP_API --insecure-skip-tls-verify

  echo ""
  echo ">>> Identity creada — viene de ldap-modern:"
  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify
  oc get identities | grep -E "NAME|modern"

  echo ""
  echo "============================================"
  echo " PAUSA — Muestra en la consola web:"
  echo " https://console-openshift-console.apps-crc.testing"
  echo " → User Management → Users     (bob_modern aparece)"
  echo " → User Management → Identities (ldap-modern como IDP)"
  echo ""
  echo " Puedes intentar login manual en la consola:"
  echo "   IDP: ldap-modern  Usuario: bob_modern  Password: Password123!"
  echo "   → Debe funcionar"
  echo "============================================"
  echo "Pulsa ENTER para continuar..."
  read
}

# =============================================================================
#  PASO 3 — Caso A: Habilitar ECDHE en el servidor legacy
#  "Si no podéis migrar a TLS 1.3 de golpe, esta es la solución intermedia"
# =============================================================================

demo_paso3_casoA() {
  echo ""
  echo "============================================"
  echo " PASO 3 — Caso A: Habilitar ECDHE"
  echo "============================================"

  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify

  # Limpia identidades previas
  echo ">>> Limpiando identidades previas..."
  oc delete user bob_legacy carol_legacy 2>/dev/null || true
  oc get identities -o name 2>/dev/null | grep -E "ldap-legacy|keycloak-broker" \
    | xargs -I{} oc delete {} 2>/dev/null || true

  echo ">>> Aplicando fix — añadiendo +ECDHE-RSA y +CURVE-ALL al cipher suite:"
  oc set env deploy/openldap-legacy -n legacy-auth \
    LDAP_TLS_CIPHER_SUITE='NONE:+VERS-TLS1.2:+ECDHE-RSA:+RSA:+AES-128-GCM:+AES-256-GCM:+AES-128-CBC:+AES-256-CBC:+MAC-ALL:+SIGN-ALL:+CTYPE-X509:+COMP-ALL:+CURVE-ALL'

  _ldap_cleanup_and_restart "ECDHE-RSA + RSA Kx — estado arreglado"
  _wait_for_slapd_tls
  _populate_legacy_users
  _refresh_oauth
  _verify_ldap_from_oauth

  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify

  echo ""
  echo ">>> Verificando cipher suite — ahora debe mostrar ECDHE:"
  LEGACY_POD=$(oc get pod -n legacy-auth -l app=openldap-legacy -o jsonpath='{.items[0].metadata.name}')
  oc exec -n legacy-auth "$LEGACY_POD" -- \
    bash -c 'echo Q | openssl s_client -connect localhost:636 -tls1_2 2>&1 | grep -E "Cipher|Protocol"' || true

  echo ""
  echo ">>> bob_legacy ahora funciona (con retry):"
  local login_ok=false
  for attempt in $(seq 1 5); do
    if oc login -u bob_legacy -p 'Password123!' $OCP_API --insecure-skip-tls-verify 2>&1 | grep -q "Login successful"; then
      echo "    Login exitoso (intento $attempt)"
      login_ok=true
      break
    fi
    echo "    Reintentando... ($attempt/5)"
    sleep 5
  done
  if [ "$login_ok" = false ]; then
    echo "    WARN: login falló tras 5 intentos — verificar logs:"
    oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify
    oc logs -n openshift-authentication deploy/oauth-openshift --tail=5 2>&1 \
      | grep -i -E "legacy|error|bob"
  fi

  echo ""
  echo ">>> Identities — bob_legacy viene de ldap-legacy:"
  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify
  oc get identities | grep -E "NAME|legacy"

  echo ""
  echo "============================================"
  echo " PAUSA — Muestra en la consola web:"
  echo " https://console-openshift-console.apps-crc.testing"
  echo " → User Management → Users     (bob_legacy aparece)"
  echo " → User Management → Identities (ldap-legacy como IDP)"
  echo ""
  echo " Puedes intentar login manual en la consola:"
  echo "   IDP: ldap-legacy  Usuario: bob_legacy  Password: Password123!"
  echo "   → Debe funcionar (TLS 1.2 + ECDHE)"
  echo ""
  echo " Cipher suite activo en el servidor:"
  echo "   TLSv1.2 — ECDHE-RSA-AES256-GCM-SHA384"
  echo "============================================"
  echo "Pulsa ENTER para continuar..."
  read
}

# =============================================================================
#  PASO 4 — Caso C: Keycloak como broker OIDC
#  "Si no podéis tocar el AD, esta es la solución sin cambios en el servidor"
# =============================================================================

demo_paso4_casoC() {
  echo ""
  echo "============================================"
  echo " PASO 4 — Caso C: Keycloak como broker"
  echo "============================================"

  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify

  demo_check_keycloak

  # Vuelve ldap-legacy al estado roto para que OCP no pueda autenticar directamente
  echo ">>> Revirtiendo ldap-legacy a cipher suite roto (solo RSA Kx)..."
  oc set env deploy/openldap-legacy -n legacy-auth \
    LDAP_TLS_CIPHER_SUITE='NONE:+VERS-TLS1.2:+RSA:+AES-128-GCM:+AES-256-GCM:+AES-128-CBC:+AES-256-CBC:+MAC-ALL:+SIGN-ALL:+CTYPE-X509:+COMP-ALL'

  _ldap_cleanup_and_restart "solo RSA Kx — estado roto para demostrar broker"
  _wait_for_slapd_tls
  _populate_legacy_users
  _refresh_oauth

  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify

  # Borra Identity y User previos de carol_legacy
  echo ">>> Limpiando Identity previa de carol_legacy..."
  oc delete user carol_legacy 2>/dev/null || true
  oc get identities -o name 2>/dev/null | grep carol | xargs -I{} oc delete {} 2>/dev/null || true

  echo ""
  echo ">>> ldap-legacy ROTO para OCP — pero Keycloak puede hablar con él (Java, no Go):"
  oc exec -n keycloak keycloak-0 -- bash -c '
    mkdir -p /tmp/kc
    /opt/keycloak/bin/kcadm.sh config credentials \
      --config /tmp/kc/cfg \
      --server http://localhost:8080 \
      --realm master \
      --user temp-admin \
      --password '"$KC_PASS"' 2>/dev/null
    echo "--- Federaciones configuradas: ---"
    /opt/keycloak/bin/kcadm.sh get components \
      --config /tmp/kc/cfg -r master \
      -q type=org.keycloak.storage.UserStorageProvider \
      --fields name,providerId 2>/dev/null'

  echo ""
  echo ">>> Sincronizando usuarios desde ldap-legacy a Keycloak..."
  oc exec -n keycloak keycloak-0 -- bash -c '
    /opt/keycloak/bin/kcadm.sh config credentials \
      --config /tmp/kc/cfg \
      --server http://localhost:8080 \
      --realm master \
      --user temp-admin \
      --password '"$KC_PASS"' 2>/dev/null

    # Extraer el ID: buscar la línea "ldap-legacy", subir 1 línea al campo "id"
    LEGACY_ID=$(/opt/keycloak/bin/kcadm.sh get components \
      --config /tmp/kc/cfg -r master \
      -q type=org.keycloak.storage.UserStorageProvider \
      --fields id,name 2>/dev/null \
      | grep -B1 "ldap-legacy" | head -1 | tr -d " \"," | sed "s/id://")

    if [ -z "$LEGACY_ID" ]; then
      echo "ERROR: No se encontró la federación ldap-legacy"
      exit 1
    fi

    echo "Federation ID: $LEGACY_ID"
    /opt/keycloak/bin/kcadm.sh create \
      "user-storage/$LEGACY_ID/sync?action=triggerFullSync" \
      --config /tmp/kc/cfg -r master 2>/dev/null
    echo "Sync completado"'

  echo ""
  echo ">>> carol_legacy se autentica en Keycloak (Java, sin restricción de Go):"
  oc exec -n keycloak keycloak-0 -- bash -c '
    /opt/keycloak/bin/kcadm.sh config credentials \
      --config /tmp/kc/test \
      --server http://localhost:8080 \
      --realm master \
      --user carol_legacy \
      --password "Password123!"'

  echo ""
  echo ">>> carol_legacy falla contra OCP directamente (ldap-legacy roto):"
  oc login -u carol_legacy -p 'Password123!' $OCP_API --insecure-skip-tls-verify || true

  echo ""
  echo "============================================"
  echo " ACCIÓN: Abre el navegador"
  echo " URL: https://console-openshift-console.apps-crc.testing"
  echo " Selecciona: keycloak-broker"
  echo " Usuario: carol_legacy  Password: Password123!"
  echo "============================================"
  echo ">>> Pulsa ENTER cuando carol_legacy haya entrado por la consola web..."
  read

  echo ""
  echo ">>> Identity — viene de keycloak-broker, no de ldap-legacy directo:"
  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify
  oc get identities | grep -E "NAME|carol|keycloak"

  echo ""
  echo "============================================"
  echo " PAUSA — Muestra en la consola web:"
  echo " https://console-openshift-console.apps-crc.testing"
  echo " → User Management → Users     (carol_legacy aparece)"
  echo " → User Management → Identities (keycloak-broker como IDP)"
  echo ""
  echo " El AD legacy sigue roto para OCP directamente"
  echo " pero carol_legacy entró via Keycloak como broker"
  echo "============================================"
  echo "Pulsa ENTER para continuar..."
  read
}

# =============================================================================
#  RESUMEN FINAL
# =============================================================================

demo_resumen() {
  echo ""
  echo "============================================"
  echo " RESUMEN"
  echo "============================================"
  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify
  echo ">>> Todos los usuarios e identidades creados durante la demo:"
  oc get users
  echo ""
  oc get identities
}

# =============================================================================
#  DIAGNÓSTICO — para debugging entre pasos
# =============================================================================

demo_diag() {
  echo ""
  echo "============================================"
  echo " DIAGNÓSTICO"
  echo "============================================"

  oc login -u kubeadmin -p $KUBEADMIN_PASS $OCP_API --insecure-skip-tls-verify 2>/dev/null

  echo "=== Pod ==="
  oc get pods -n legacy-auth -l app=openldap-legacy -o wide

  echo ""
  echo "=== Service ClusterIP ==="
  oc get svc openldap-legacy -n legacy-auth -o jsonpath='  ClusterIP: {.spec.clusterIP}{"\n"}'

  echo ""
  echo "=== Endpoints ==="
  oc get endpoints openldap-legacy -n legacy-auth -o jsonpath='  Pod IP: {.subsets[0].addresses[0].ip}{"\n"}' 2>/dev/null

  echo ""
  echo "=== Cipher TLS (desde dentro del pod) ==="
  LEGACY_POD=$(oc get pod -n legacy-auth -l app=openldap-legacy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  oc exec -n legacy-auth "$LEGACY_POD" -- \
    bash -c 'echo Q | openssl s_client -connect localhost:636 -tls1_2 2>&1 | grep -E "Cipher|Protocol"' 2>/dev/null || echo "  Pod no disponible"

  echo ""
  echo "=== Cipher TLS (desde OAuth pod via Service) ==="
  _verify_ldap_from_oauth

  echo ""
  echo "=== LDAP search (bind autenticado) ==="
  oc exec -n legacy-auth "$LEGACY_POD" -- ldapsearch -x \
    -H ldap://localhost \
    -D "cn=admin,dc=legacy,dc=local" \
    -w AdminPass123! \
    -b "ou=users,dc=legacy,dc=local" uid 2>/dev/null | grep "uid:" || echo "  No users found"

  echo ""
  echo "=== OAuth logs (últimas líneas con error) ==="
  oc logs -n openshift-authentication deploy/oauth-openshift --tail=10 2>&1 \
    | grep -i -E "legacy|error|ldap|EOF|No Such" | tail -3 || echo "  Sin errores recientes"
}

# =============================================================================
#  USO:
#
#  pre_demo            — preparar entorno antes de la demo
#  demo_paso1_fallo    — mostrar el fallo (EOF)
#  demo_paso2_casoB    — TLS 1.3 como solución ideal
#  demo_paso3_casoA    — ECDHE como solución intermedia
#  demo_paso4_casoC    — Keycloak como broker sin tocar el AD
#  demo_resumen        — tabla final de usuarios e identidades
#  demo_diag           — diagnóstico rápido del estado actual
# =============================================================================
