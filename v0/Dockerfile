FROM node:22-bookworm-slim AS codex
COPY lasa_service/config_defaults.json /tmp/lasa-config-defaults.json
RUN npm install --global "@openai/codex@$(node -p 'require("/tmp/lasa-config-defaults.json").runtime.expected_version')"

FROM python:3.12-slim-bookworm
COPY --from=codex /usr/local/lib/node_modules/@openai /opt/openai
RUN python -c "from pathlib import Path; import shutil; candidates=[p for p in Path('/opt/openai').rglob('codex') if p.is_file() and p.stat().st_mode & 0o111 and p.read_bytes()[:4]==b'\x7fELF']; assert len(candidates)==1,candidates; shutil.copyfile(candidates[0],'/usr/local/bin/codex'); Path('/usr/local/bin/codex').chmod(0o755)" \
    && rm -rf /opt/openai
COPY lasa_service/container_entry.py /opt/lasa/
ENV HOME=/home/lasa CODEX_HOME=/home/lasa TMPDIR=/tmp LANG=C.UTF-8
ENTRYPOINT ["python3", "-I", "-S", "/opt/lasa/container_entry.py"]
CMD ["serve", "/usr/local/bin/codex"]
