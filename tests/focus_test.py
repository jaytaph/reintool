# /// script
# requires-python = ">=3.11"
# dependencies = ["textual>=1.0", "httpx>=0.27"]
# ///
import asyncio, sys
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
sys.argv = ["x"]
import httpx, reins_qa_tool as t
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from fake_api_test import handler
async def main():
    api = t.Api("http://fake", True, log=None)
    api.http = httpx.AsyncClient(base_url="http://fake", transport=httpx.MockTransport(handler))
    app = t.ReinsQATool(api)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("n"); await pilot.pause(0.2)
        seq = [app.focused.id]
        for k in ["tab", "tab", "tab", "shift+tab"]:
            await pilot.press(k); await pilot.pause(0.05)
            seq.append(app.focused.id)
        print("focus sequence:", seq)
        # main-screen shortcuts must still be blocked in the modal
        await pilot.press("tab", "tab", "tab"); await pilot.pause(0.05)  # onto a non-input widget
        before = len(app.screen_stack)
        await pilot.press("n", "g"); await pilot.pause(0.2)
        print("focused:", type(app.focused).__name__, "stack before/after n,g:", before, len(app.screen_stack))
asyncio.run(main())
