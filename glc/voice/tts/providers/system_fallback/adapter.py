"""System TTS fallback (`say` on macOS, `pyttsx3` elsewhere).

This is the one TTS provider that ships fully implemented. The other
four (kokoro, elevenlabs, cartesia, gemini_live) are group-assignment
stubs. A fresh install can serve `/v1/speak?prefer=fallback` from day
one through this provider.
"""

from __future__ import annotations

import base64
import platform
import shutil
import tempfile
from pathlib import Path

from glc.security import exec_guard
from glc.voice.tts.base import SynthesizeResult, TTSError, TTSProvider

# Finding B8: synthesis is bounded like every other shell-out (invariant 8).
SAY_TIMEOUT_S = 60


class Provider(TTSProvider):
    name = "system_fallback"

    async def synthesize(self, text: str, voice_id: str | None = None) -> SynthesizeResult:
        sysname = platform.system()
        if sysname == "Darwin" and shutil.which("say"):
            return self._macos_say(text)
        return self._pyttsx3(text)

    @staticmethod
    def _macos_say(text: str) -> SynthesizeResult:
        """Finding B8: the text used to be passed as a bare argv element --
        `say -o out <text>` -- so any user text beginning with '-' was parsed
        by `say` as an option instead of speech (argument injection). It now
        travels in a file (`say -f`), which keeps user data out of argv
        entirely rather than trying to sanitise it. The binary is resolved
        through the exec guard (no PATH hijack) and the run is bounded.
        """
        with tempfile.NamedTemporaryFile(suffix=".aiff", delete=False) as f:
            out = Path(f.name)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write(text)
            text_file = Path(f.name)
        try:
            say = exec_guard.resolve_binary("say")
            exec_guard.run(
                [say, "-o", str(out), "-f", str(text_file)],
                timeout=SAY_TIMEOUT_S,
                check=True,
            )
            data = out.read_bytes()
        finally:
            out.unlink(missing_ok=True)
            text_file.unlink(missing_ok=True)
        return SynthesizeResult(
            audio_b64=base64.b64encode(data).decode("ascii"),
            mime="audio/aiff",
            sample_rate=22050,
            provider="system_fallback",
            cost_usd=0.0,
        )

    @staticmethod
    def _pyttsx3(text: str) -> SynthesizeResult:
        try:
            import pyttsx3  # type: ignore
        except Exception as e:
            raise TTSError(f"no system TTS available: {e}") from e
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            out = Path(f.name)
        try:
            engine = pyttsx3.init()
            engine.save_to_file(text, str(out))
            engine.runAndWait()
            data = out.read_bytes()
        finally:
            out.unlink(missing_ok=True)
        return SynthesizeResult(
            audio_b64=base64.b64encode(data).decode("ascii"),
            mime="audio/wav",
            sample_rate=22050,
            provider="system_fallback",
            cost_usd=0.0,
        )
