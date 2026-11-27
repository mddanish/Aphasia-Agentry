import asyncio

from aphasia.tui.app import SECTIONS, AphasiaApp
from aphasia.tui.data import load_demo


def test_every_section_renders():
    async def go():
        app = AphasiaApp(load_demo())
        async with app.run_test(size=(120, 40)) as pilot:
            for i, (sid, _) in enumerate(SECTIONS):
                await pilot.press(str(i + 1))
                await pilot.pause()
                assert app.current == sid
                await pilot.press("down")
    asyncio.run(go())
