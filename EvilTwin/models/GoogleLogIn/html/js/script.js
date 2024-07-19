function showpass() {
  var passwd = window.getComputedStyle(document.getElementById("password")).fontFamily;
  var passwd_ = document.getElementById("password")
  if (passwd === 'Roboto, sans-serif') {
    passwd_.style.fontFamily = 'password';
  } else {
    passwd_.style.fontFamily = 'Roboto, sans-serif';
  }
}

function fixoverride() {
  var input_element = document.querySelector("input");

  document.addEventListener("click", function () {
    input_element.setAttribute("value", input_element.value);
    document.getElementById("placeholder_").style.cssText = "font-size:12px;";
  });
}
