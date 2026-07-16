"""whisper.cpp wrapper shim.

Expects a `whisper-cli` binary on PATH and a base model at
~/.glc/models/whisper-base/ggml-base.bin. Invokes the binary as a
subprocess, parses the JSON output, returns (text, language,
duration_ms). The model download is handled by the install script.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from glc.security import exec_guard

MODEL_DIR = Path(os.path.expanduser(os.getenv("GLC_WHISPER_MODEL_DIR", "~/.glc/models/whisper-base")))
MODEL_FILE = MODEL_DIR / "ggml-base.bin"

# No-speech threshold for whisper-cli; default speech-probability cut.
VAD_THRESHOLD = 0.6
# If every output segment reports no_speech_prob above this, the audio
# contains no speech (e.g. music-only) and we return an empty transcript.
NO_SPEECH_DISCARD = 0.7

# Performance tuning — override via env vars without code changes.
# Thread count: defaults to all logical CPUs; linear speedup up to ~8 cores.
_DEFAULT_THREADS = os.cpu_count() or 4
WHISPER_THREADS = int(os.getenv("GLC_WHISPER_THREADS", str(_DEFAULT_THREADS)))
# Beam size: 1=greedy (fastest), 5=default accuracy. 2 halves decoding cost
# with negligible accuracy loss on typical speech.
WHISPER_BEAM_SIZE = int(os.getenv("GLC_WHISPER_BEAM_SIZE", "2"))

# Finding B8: whisper transcription is not fast, but it is bounded. An
# unbounded subprocess is a free denial of service (invariant 8).
WHISPER_TIMEOUT_S = int(os.getenv("GLC_WHISPER_TIMEOUT_S", "300"))


def run_whisper_cpp(audio: bytes, mime: str, use_vad: bool = False) -> tuple[str, str, int]:
    # Finding B8: resolve through the exec guard, not shutil.which(). which()
    # honours PATH, and in-process code can prepend its own directory and have
    # a "transcription" execute its binary instead. resolve_binary() refuses
    # anything outside a trusted bin dir.
    try:
        cli = exec_guard.resolve_binary("whisper-cli")
    except exec_guard.ExecNotPermitted:
        try:
            cli = exec_guard.resolve_binary("whisper.cpp")
        except exec_guard.ExecNotPermitted as e:
            raise RuntimeError(
                f"whisper-cli is not usable: {e}. Install whisper.cpp and place its "
                "'whisper-cli' binary in a trusted bin dir, or use prefer='default' for Groq."
            ) from None
    if not MODEL_FILE.exists():
        raise RuntimeError(
            f"whisper base model not found at {MODEL_FILE}. Run "
            "`daemon/install.sh --models` or download manually."
        )
    suffix = ".wav" if "wav" in mime else ".bin"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(audio)
        audio_path = Path(f.name)
    try:
        cmd = [
            cli,
            "-m",
            str(MODEL_FILE),
            "-f",
            str(audio_path),
            "-oj",
            "-t",
            str(WHISPER_THREADS),  # use all cores → linear speedup
            "-bs",
            str(WHISPER_BEAM_SIZE),  # beam=2 ≈ 2× faster vs default 5
        ]
        # For long inputs, raise the no-speech threshold so whisper drops
        # no-speech segments more aggressively. `-nth` is model-free; the
        # native `--vad` flag would require a separate Silero VAD model.
        if use_vad:
            cmd.extend(["-nth", str(VAD_THRESHOLD)])

        # B8: via the exec guard — absolute trusted binary, mandatory timeout,
        # minimal environment (the child has no business seeing the gateway's),
        # never a shell, and audited.
        out = exec_guard.run(
            cmd,
            timeout=WHISPER_TIMEOUT_S,
            capture_output=True,
            text=True,
            check=True,
        )
    finally:
        audio_path.unlink(missing_ok=True)
    json_path = audio_path.with_suffix(audio_path.suffix + ".json")
    if json_path.exists():
        d = json.loads(json_path.read_text())
        json_path.unlink(missing_ok=True)
        segments = d.get("transcription") or d.get("segments") or []
        text = " ".join((s.get("text") or "").strip() for s in segments).strip()
        language = d.get("language") or "en"
        duration_ms = int(segments[-1].get("offsets", {}).get("to", 0)) if segments else 0
        # Music-only detection: when every segment is flagged as non-speech by
        # whisper's internal classifier, discard the (hallucinated) transcript.
        # Falls back safely to 0.0 when no_speech_prob is absent (older builds).
        if segments and all(s.get("no_speech_prob", 0.0) > NO_SPEECH_DISCARD for s in segments):
            return "", language, duration_ms
        return text, language, duration_ms
    return out.stdout.strip(), "en", 0
