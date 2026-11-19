# Testing standby rounds on the local devnet

Step-by-step test of everything built on the `standby-rounds` branch: unit tests, then a fresh
devnet run that covers the first round, the round committee lookup, a dead standby going stale and
being replaced, a killed key generation, a late attestation, and a full takeover with mint and
release.

Each step is one command. Each prints a short report and also saves it to `out/<step>.out`.
When you are done, `collect` (step 12) sums up the run.

**Total time: about 6 to 8 hours**, mostly waiting: the devnet setup takes 3 to 4 hours, and the
stale-standby drill needs 120 blocks (about an hour).

## Before you start

- Run everything inside `tmux` or `screen`, so closing the terminal doesn't stop a long step:

  ```bash
  tmux new -s rounds          # later, to come back: tmux attach -t rounds
  cd utils/local-devnet/standby-rounds-test     # from the beldex checkout
  ```

- The kit tests the beldex checkout it lives in, with `bridge-contract` checked out beside it
  (`../bridge-contract`). Set `RT_REPO` or `RT_BC` to point it elsewhere. The checkout should have
  no uncommitted changes (`build` prints the commit and the changed files).
- The devnet keeps its state in `$S` (default `~/standby-e2e`); the kit writes its reports to
  `out/` here, which git ignores.
- **Step 3 wipes the current devnet.** That includes any devnet-only keys, shares and wallets in
  `utils/local-devnet/testdata`. Your files in `bridge-contract/devnet/` (`ceremony-gen*.md`) are not
  touched.

## The steps

| # | Command | Takes | What it tests |
|---|---------|-------|---------------|
| 1 | `./rt.sh build` | 1 min if up to date | The binaries match the checked-out commit |
| 2 | `./rt.sh unit` | ~10 min | C++ consensus tests for rounds, every gateway and bridge test, and all signer tests |
| 3 | `./rt.sh stop` then `./rt.sh devnet` | 1 min | Stops anything running and starts a fresh 21-node devnet (14 bridge seats) |
| 4 | `./rt.sh devnet-wait` | 3 to 4 h | Waits until the devnet is up; prints progress every 10 minutes |
| 5 | `./rt.sh bootstrap` | ~5 min | Anvil, the first key generation, the wBDX contract and the bridge gateway |
| 6 | `./rt.sh start` | 1 min | 22 live and 22 standby signers, supervised, plus the log recorder |
| 7 | `./rt.sh first` | 10 to 30 min | **First round**: consensus draws a committee, the key is generated and attested, and the live signers name it on the gateway and the contract |
| 8 | `./rt.sh committee` | seconds | **Round committee**: every node that started a round was on its committee as consensus reports it, and no member was told it wasn't |
| 9 | `./rt.sh drills` | 1.5 to 2.5 h | **A** dead standby goes stale and its holders step aside; **B** killed key generation; **C** late attestation refused; **D** one drawn member offline before its round: the round still makes the key with those that checked in, and the replacement is named on both chains |
| 10 | `./rt.sh committee` | seconds | The committee check again, now over the drill rounds too |
| 11 | `./rt.sh takeover` | 40 to 90 min | **Takeover**: the owner's signers die, a deposit goes unminted, the standby takes over on both chains, mints the deposit, releases a redeem, and gets a standby of its own |
| 12 | `./rt.sh collect` | seconds | Event counts, failure and step-aside reasons, warnings |

`./rt.sh status` prints the current picture at any time (owner, standby, stale or not, waiting
key, open rounds, the contract's signer and standby). It's safe to run while another step runs,
from a second tmux window.

### What each step should show

1. **build**: `0 changed file(s)`; make and cargo finish without errors.
2. **unit**: every `[  PASSED  ]` line and no `FAILED`; both `test result: ok.` lines.
3. **stop / devnet**: `processes left: 0`, then `fresh devnet starting`.
4. **devnet-wait**: ends with `devnet ready` and the bridge seats and committee lines.
   If it prints `!! the harness exited`, look at the last 100 lines of `$S/devnet.log`.
5. **bootstrap**: every `==` stage, then `WBDX=`, `GATEWAY_ID=`, and `exit code 0`.
6. **start**: `signers: 22 live 22 standby` and `BRIDGE_SIGNER_DKG_TIMEOUT_SECS=240`.
7. **first**: a standby key appears; `contract standby … → MATCH`; the events list shows the
   members checking in (`checked in as member …`), then `NO STANDBY: 6 of 6 members checked in;
   generating …`, keys generated, attestations, and the naming.
8. and 10. **committee**: every round `OK`, and `0 wrong` at the end.
9. **drills**:
   - A: `STALE` about 120 blocks after the last proof, and three holders stepped aside.
   - B: the members of round R1 report `standby key generation failed (… Timeout)`.
   - C: at least one refused attestation, and the same members stepping aside with
     `closed without attesting this key`.
   - D: a new standby and `MATCH`, the rounds with `k of 6 checked in`, and
     `D: CHECK-IN PASS: round … drew the paused node and still made the key with 5 of 6 members`,
     then `the paused node is drawn last`. If it says `inconclusive` (the paused node was never
     drawn, about a 1 in 4 chance), the rest still counts; rerun the drills later to see it.
11. **takeover**: `TAKEOVER complete on both chains`, supply goes up by the deposit, the reserve
    drops after the redeem with `reserve = supply`, then `new owner's standby … MATCH`.
12. **collect**: no `panicked at`; reasons that fit the drills.

A step that times out prints `!! TIMEOUT …` and stops. Don't rerun it blindly: run
`./rt.sh status` and `./rt.sh collect`, and keep those with the step's output.

## Gathering the results

When step 12 is done (or a step fails), print every report in one go:

```bash
cd utils/local-devnet/standby-rounds-test/out
for f in build unit devnet-wait bootstrap start first committee drills takeover collect; do
  [ -f $f.out ] && { echo "===== $f"; cat $f.out; }
done
```

For more detail, the full record is in `out/stamped.log` (every signer's log, one file, stamped
with time and node) and `out/standby-snapshots.jsonl` (every change of the bridge's standby state).

## Notes

- The takeover step sets the contract's takeover delay to 60 seconds; the default is 1 hour, and
  with it the step would take an hour longer.
- Pausing a signer (`kill -STOP`) is how the drills take a node offline without losing its state.
  The drills always resume what they pause; if you stop a drill midway, run
  `pkill -CONT -f 'beldex-bridge-signer serve'` to resume every signer.
- On one machine every node shares the same mesh ports, so overlapping key generations can fail
  with `Address already in use`. That is a devnet-only effect.
- `./rt.sh stop` stops the whole devnet when you are finished.
