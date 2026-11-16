// Ask before the irreversible quality-control revoke. External file because the
// Content-Security-Policy deliberately forbids inline scripts.
document.addEventListener("submit", function (event) {
  var form = event.target;
  if (!form.classList.contains("revoke-form")) return;
  var id = form.getAttribute("data-file-id") || "该文件";
  var ok = window.confirm(
    "撤销不可逆，且会立即停止本文件及其全部下游的下载。确认撤销 " + id + "？"
  );
  if (!ok) event.preventDefault();
});
