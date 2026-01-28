# AutoRE

AutoRE is a small reverse‑engineering helper for Windows PE files.

- **Ghidra headless** extracts functions, disassembly, decompiler output, pcode, and strings.
- **Web UI** lets you browse functions (left) and view AI‑assisted pseudocode (right).
- **Hybrid worker** runs the AI calls on the host (so API keys stay local).

## Requirements (fresh host)
This project assumes a Linux host (instructions/scripts target Ubuntu 22.04/24.04).

The installer script can set up:
- system packages (python venv, Java, etc.)
- Ghidra (download + extract)
- Python venv + dependencies
- `.env` from `.env.example`

Node/npm is **not required** for normal use because `frontend/dist` is committed and served by the backend.

## Quick install (fresh Ubuntu)
```bash
git clone https://github.com/Juntar0/ghidrauto-llm.git
cd ghidrauto-llm
./install_ubuntu.sh
```

### Optional: CAPA auto-install
The UI can auto-install the standalone **CAPA** binary when you click the **CAPA** button.
If you prefer manual install:
```bash
./install_capa.sh
```

Then edit `.env` and set at least one AI option:
- `ANTHROPIC_API_KEY` **or**
- `OPENAI_BASE_URL` (and optionally `OPENAI_API_KEY`)

## Run
```bash
./run_backend.sh
./run_worker.sh
```

Open:
- `http://<host>:5555/`

## Notes
### Settings
Most knobs are configured in the UI via **Settings** (stored in browser localStorage):
- provider + model
- OpenAI-compatible endpoint base URL (supports `/v1` included or not)
- API mode: `chat.completions` or `responses`
- reasoning effort: `low|medium|high` (if supported)
- Find main automation (auto-run top N)
- guardrail (retry loop) parameters

### Strings
Strings are extracted from Ghidra defined data into `work/<job>/extract/analysis.json` and can be viewed via **Strings** in the UI.

Existing jobs created before the strings feature require **Re-extract**.

## Security / Git hygiene
- **Never commit `.env`** (contains secrets). It is gitignored.
- Do not commit runtime artifacts:
  - `work/` (uploaded binaries, analysis outputs, queues)
  - `logs/`

Before pushing:
```bash
git status
# ensure .env / work/ / logs/ are not staged
```
