# Wazuh 4.14.11 single-node for the lab

Needs: Docker + Compose v2, 4 vCPU, 8 GB RAM free, 20 GB disk. Linux host or VM.

```bash
# 1. kernel setting for the indexer
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf

# 2. official docker deployment
git clone -b v4.14.11 --depth 1 https://github.com/wazuh/wazuh-docker.git ~/wazuh-docker
cd ~/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator

# 3. Aphasia mounts (rules, lists, fixture logs)
export APHASIA_REPO=/path/to/Aphasia-Agentry          # absolute path
cp "$APHASIA_REPO/deploy/wazuh/docker-compose.override.yml" .
mkdir -p "$APHASIA_REPO/fixture/logs" && chmod 777 "$APHASIA_REPO/fixture/logs"
touch "$APHASIA_REPO/fixture/logs/fixture.jsonl" && chmod 666 "$APHASIA_REPO/fixture/logs/fixture.jsonl"
mkdir -p "$APHASIA_REPO/engine/runs/proxy" && touch "$APHASIA_REPO/engine/runs/proxy/proxy.jsonl"   # proxy mode log

# 4. manager config: add the two <localfile> and two <list> entries from
#    $APHASIA_REPO/deploy/wazuh/manager-ossec-snippet.xml into config/wazuh_cluster/wazuh_manager.conf
#    (<localfile> inside <ossec_config>; the two <list> lines inside the existing <ruleset>)

# 5. start
docker compose up -d
docker compose ps
```

Defaults from the wazuh-docker README (change before any non-lab use):
- Dashboard `https://<vm>:443` — `admin` / `SecretPassword`
- Indexer `https://<vm>:9200` — `admin` / `SecretPassword`
- API `https://<vm>:55000` — `wazuh-wui` / `MyS3cr37P450r.*-`
Check the README of the cloned tag for the current values.

## Verify rules

```bash
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest
# paste one line from deploy/wazuh/samples/telemetry.jsonl, compare with samples/expected.md
```

After editing `aphasia_rules.xml` or a list: `docker compose restart wazuh.manager`.

## Verify end to end

```bash
echo '{"ts":"2026-12-04T10:15:04Z","source":"aphasia-fixture","component":"agent","event":"tool_call","tool":"issue_refund","mutating":true,"args":{"order_id":"x","payee":"unknown-1"},"honey":true,"session":"t"}' >> "$APHASIA_REPO/fixture/logs/fixture.jsonl"

curl -sk -u admin:SecretPassword "https://localhost:9200/wazuh-alerts-4.x-*/_search?q=rule.id:100210&size=1" | head -c 600
```

## Connect Aphasia

Easiest: `aphasia setup` → step 5 SIEM · Wazuh (URL, user, password, CA path), `ctrl+t` to test.
CA file: `~/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem`.
Or by env for one shell: `APHASIA_WAZUH_URL=https://<vm>:9200` and `APHASIA_WAZUH_PASSWORD` (`read -rs`).

## Troubleshooting

| Symptom | Check |
|---|---|
| Indexer restarts | `vm.max_map_count`, RAM |
| No alerts | file mounted? `docker compose exec wazuh.manager tail /var/log/aphasia/fixture.jsonl`; `<localfile>` added? `grep aphasia /var/ossec/logs/ossec.log` |
| Rule not matching | `wazuh-logtest`; JSON booleans arrive as `true` strings; nested args are `args.payee` |
| Alert appears late | normal 2–10 s; detect window-after defaults to 90 s |
