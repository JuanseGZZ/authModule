export function showView(viewId) {
  const all = Array.from(document.querySelectorAll('.view'));
  for (const el of all) {
    if (el.id === viewId) {
      el.hidden = false;
    } else {
      el.hidden = true;
    }
  }
}
