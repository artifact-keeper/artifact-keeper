#!/usr/bin/env bash
# Cross-tenant read/write proof for #2504.
# Usage: prove.sh <BASE_URL> <DB_CONTAINER> <LABEL>
set -uo pipefail
BASE="$1"; DBC="$2"; LABEL="$3"
ADMPASS="TestRunner!2026secure"
APASS="AlicePass!2026x"
SUF="$RANDOM$RANDOM"
MVA="mvn-a-$SUF"; MVB="mvn-b-$SUF"
COORD="com/secret/app/1.0-$SUF/app-1.0-$SUF.jar"
SECRET="MVNB-SECRET-BYTES-$SUF"
EVIL="ALICE-EVIL-CLOBBER-$SUF"
OWN="ALICE-OWN-BYTES-$SUF"
OWNCOORD="com/alice/lib/2.0-$SUF/lib-2.0-$SUF.jar"

jqr(){ jq -r "$1" 2>/dev/null; }
login(){ curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jqr '.access_token // empty'; }
code(){ # METHOD PATH TOKEN [BODY] [CT]
  local m="$1" p="$2" t="$3" b="${4:-}" ct="${5:-application/octet-stream}"
  if [ -n "$b" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H "Content-Type: $ct" --data-binary "$b"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t"
  fi; }
body(){ curl -s -X "$1" "$BASE$2" -H "Authorization: Bearer $3"; }

echo "############ PROOF: $LABEL  ($BASE) ############"
TOK=$(login admin "$ADMPASS"); [ -z "$TOK" ] && { echo "admin login FAILED"; exit 1; }

# alice
curl -s -X POST "$BASE/api/v1/users" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice-$SUF\",\"email\":\"alice-$SUF@t.test\",\"password\":\"$APASS\",\"is_admin\":false}" >/dev/null
# repos (maven, local) — default storage_backend inherits the stack's STORAGE_BACKEND
for k in "$MVA" "$MVB"; do
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"key\":\"$k\",\"name\":\"$k\",\"format\":\"maven\",\"repo_type\":\"local\"}" >/dev/null
done
# grant alice developer(write) on MVA only; NO grant on MVB
docker exec "$DBC" psql -U registry -d artifact_registry -tAc "
  INSERT INTO role_assignments (user_id, role_id, repository_id)
  SELECT u.id, r.id, repo.id FROM users u, roles r, repositories repo
  WHERE u.username='alice-$SUF' AND r.name='developer' AND repo.key='$MVA'
  ON CONFLICT DO NOTHING;" >/dev/null
ATOK=$(login "alice-$SUF" "$APASS"); [ -z "$ATOK" ] && { echo "alice login FAILED"; exit 1; }

echo "-- backend storage_backend of repos:"
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT key||' -> '||storage_backend FROM repositories WHERE key IN ('$MVA','$MVB');" 2>/dev/null || \
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT key||' -> '||storage_backend FROM repositories WHERE key LIKE 'mvn-%-$SUF';"

# admin uploads the private secret into MVB at COORD
UP_B=$(code PUT "/maven/$MVB/$COORD" "$TOK" "$SECRET")
echo "-- [setup] admin PUT secret into $MVB/$COORD => $UP_B (expect 201)"
DL_B=$(body GET "/maven/$MVB/$COORD" "$TOK")
echo "-- [setup] admin GET $MVB/$COORD => '$DL_B'"

echo
echo "== A. CROSS-REPO READ (alice reads MVA for a coord that exists only in MVB) =="
RC=$(code GET "/maven/$MVA/$COORD" "$ATOK")
RB=$(body GET "/maven/$MVA/$COORD" "$ATOK")
echo "   alice GET $MVA/$COORD => HTTP $RC ; body='$RB'"
if [ "$RC" = "200" ] && [ "$RB" = "$SECRET" ]; then echo "   >>> LEAK: alice read MVB's secret bytes via MVA"; \
  elif [ "$RC" = "404" ] || [ "$RC" = "403" ]; then echo "   >>> DENIED (no bytes leaked)"; else echo "   >>> UNEXPECTED"; fi
echo "   (control) alice GET $MVB directly => $(code GET "/maven/$MVB/$COORD" "$ATOK") (expect 403/404, no grant)"

echo
echo "== B. CROSS-REPO WRITE (alice PUTs colliding coord into her own MVA) =="
WC=$(code PUT "/maven/$MVA/$COORD" "$ATOK" "$EVIL")
echo "   alice PUT $MVA/$COORD (colliding key) => HTTP $WC"
AFTER=$(body GET "/maven/$MVB/$COORD" "$TOK")
echo "   admin GET $MVB/$COORD after alice's write => '$AFTER'"
if [ "$WC" = "409" ] && [ "$AFTER" = "$SECRET" ]; then echo "   >>> REFUSED; MVB bytes intact"; \
  elif [ "$AFTER" = "$EVIL" ]; then echo "   >>> POISONED: MVB now serves alice's bytes"; else echo "   >>> WC=$WC AFTER='$AFTER'"; fi

echo
echo "== C. NO-REGRESSION (alice hosted upload+download to her OWN repo) =="
OC=$(code PUT "/maven/$MVA/$OWNCOORD" "$ATOK" "$OWN")
OB=$(body GET "/maven/$MVA/$OWNCOORD" "$ATOK")
echo "   alice PUT $MVA/$OWNCOORD => $OC ; GET => '$OB' (expect 201 + matching bytes)"
OC2=$(code PUT "/maven/$MVA/$OWNCOORD" "$ATOK" "${OWN}-v2")
echo "   alice same-repo overwrite PUT again => $OC2 (expect 201, same-repo allowed)"

echo
echo "== D. READ-LEG sidecars (checksum + metadata) cross-repo =="
# admin stores a checksum sidecar + a group-level metadata file into MVB (no rows)
CKSUM="B-CHECKSUM-$SUF"; META="B-PRIVATE-METADATA-$SUF"
METAPATH="com/secret/app/maven-metadata.xml"
echo "   [setup] admin PUT $MVB/$COORD.sha1 => $(code PUT "/maven/$MVB/$COORD.sha1" "$TOK" "$CKSUM" "text/plain")"
echo "   [setup] admin PUT $MVB/$METAPATH => $(code PUT "/maven/$MVB/$METAPATH" "$TOK" "$META" "text/xml")"
# D1 cross-repo checksum sidecar (maven.rs:907/922)
CKC=$(code GET "/maven/$MVA/$COORD.sha1" "$ATOK"); CKB=$(body GET "/maven/$MVA/$COORD.sha1" "$ATOK")
echo "   D1 alice GET $MVA/$COORD.sha1 => HTTP $CKC ; body='$CKB'"
[ "$CKC" = "200" ] && [ "$CKB" = "$CKSUM" ] && echo "      >>> LEAK: B's checksum bytes" || { [ "$CKC" = "404" ] && echo "      >>> DENIED"; }
# D2 cross-repo metadata (maven.rs:1299)
MTC=$(code GET "/maven/$MVA/$METAPATH" "$ATOK"); MTB=$(body GET "/maven/$MVA/$METAPATH" "$ATOK")
echo "   D2 alice GET $MVA/$METAPATH => HTTP $MTC ; body='$MTB'"
echo "$MTB" | grep -q "$META" && echo "      >>> LEAK: B's private metadata" || { [ "$MTC" = "404" ] && echo "      >>> DENIED (no B metadata)"; }
# D3 same-repo checksum still served (computed from alice's OWN row) — no regression
OWNCK=$(code GET "/maven/$MVA/$OWNCOORD.sha1" "$ATOK")
echo "   D3 alice GET own $MVA/$OWNCOORD.sha1 => HTTP $OWNCK (expect 200, computed from own row)"

echo
echo "== E. WRITE soft-delete carve-out =="
SDCOORD="com/victim/mod/3.0-$SUF/mod-3.0-$SUF.jar"; SDB="VICTIM-BYTES-$SUF"
echo "   [setup] admin PUT $MVB/$SDCOORD => $(code PUT "/maven/$MVB/$SDCOORD" "$TOK" "$SDB")"
# soft-delete B's row (physical object persists)
docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "UPDATE artifacts SET is_deleted=true WHERE storage_key='maven/$SDCOORD';" >/dev/null
DELCNT=$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT count(*) FROM artifacts WHERE storage_key='maven/$SDCOORD' AND is_deleted=true;")
echo "   [setup] soft-deleted B rows at key: $DELCNT"
SDC=$(code PUT "/maven/$MVA/$SDCOORD" "$ATOK" "ALICE-POISON-$SUF")
echo "   E1 alice PUT colliding $MVA/$SDCOORD (B soft-deleted) => HTTP $SDC"
[ "$SDC" = "409" ] && echo "      >>> REFUSED (poison-on-resurrect blocked)" || { [ "$SDC" = "201" ] && echo "      >>> ALLOWED (would poison on resurrect)"; }

echo "############ END $LABEL ############"
echo
