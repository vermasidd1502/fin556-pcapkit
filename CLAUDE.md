# Rules for an AI agent driving pcapkit on the FIN556 lab VM

THIS IS HFT! NOT SHEEPLE CODING!!!

You help the user pull market data from the course captures with this kit. The class rules file (`CLAUDE.md` /
`GEMINI.md` / `AGENTS.md` from fin556-claude-vm-guide) still applies in full: don't touch the system, don't leak the
data, no downloading data onto the VM, **never fill the shared disk**.

## How to run a request
1. **Ask the user** (short questions, one message): where the data is if they know (else keep `roots = auto`), which venues (Nasdaq, CME), which symbols or futures, which
   dates, which time window (New York time), bar sizes, and whether they want every quote and trade.
   Suggest defaults from `prefs.ini`. Don't guess symbols or dates they didn't ask for.
2. Write their answers into `prefs.ini`. Show them the lines you changed.
3. Run `python3 kit.py scan` (read-only) and show the summary table: which exchanges, protocols, dates and sizes exist.
   If the user's data isn't there, ask for the folder and set `roots`. Never guess paths outside the data folders.
   Then `python3 kit.py plan`.
4. Show the plan: days to pull, days missing and why, disk estimate, free space. **Wait for a yes.**
5. Run `nohup python3 kit.py run --yes > kit_run.log 2>&1 &` and tell the user how to check on it
   (`tail -f kit_run.log`). Report each day's result in one line, not the logs.
6. When done: row counts and the first 3 rows of one file only. End with a `cleaned:` line.

## Hard limits
- Read-only on `/db_pcaps`, `/md/...` and any other data folder. Write only inside the kit's output folder.
- Never start a run the plan marks "NOT ENOUGH". Offer a smaller request instead (fewer days, symbols, shorter window).
- Never go above 32 threads. Never run two `kit.py run` jobs at once.
- Don't copy output files to git, email, chats or personal drives. Results go to the course's approved storage, then
  get deleted from the VM.
- CME futures need SecurityIDs (no definitions in the captures). If the user names a contract you have no id for,
  run `python3 kit.py discover-cme --date …` and show the busiest ids with their prices; let the user pick.
- If a parser fails, show the last lines of that day's log and the exact error. Don't hide failures.

## Changing the code
Start simple and test against the reference: the single-threaded parsers (`itch_fast`, `mdp3_fast`) are the unit
test. Any faster version must give byte-identical output (`engine/bench_v3.sh`). Never one thread doing both reads
and writes.
