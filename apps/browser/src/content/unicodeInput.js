function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function sleep2() {
  await sleep(300);
  list = document.getElementsByTagName("input");
  for (let index = 0; index < list.length; index++) {
    if (list[index].type == "password") {
      pass = list[index];
      rect1 = pass.getBoundingClientRect();

      pass2 = pass.cloneNode();
      tempId = "passwordTemp" + index;
      pass2.id = tempId;
      pass2.type = "text";

      pass2.style.position = "absolute";
      pass2.style.background = "#00000000";
      pass2.style.borderColor = "#00000000";
      pass2.style.color = "#00000000";
      pass.parentNode.insertBefore(pass2, pass.nextSibling);
      labels = document.getElementsByTagName("label");
      for (let labelIndex = 0; labelIndex < labels.length; labelIndex++) {
        if (labels[labelIndex].htmlFor == pass.id) {
          labels[labelIndex].htmlFor = pass2.id;
        }
      }
      pass2.addEventListener("input", (event) => {
        list[index].value = document.getElementById("passwordTemp" + index).value;
        const inputEvent = new Event("input", {
          bubbles: true,
          cancelable: true,
        });
        if (list[index].value != "") {
          document.getElementById(list[index].id).dispatchEvent(inputEvent);
        }
        // pass.value = document.getElementById(tempId).value   多个匹配会出现错误
      });
      rect2 = pass2.getBoundingClientRect();
      offsetTop = rect2.top - rect1.top;
      offsetLeft = rect2.left - rect1.left;
      pass2.style.top =
        parseFloat(window.getComputedStyle(pass2, null).getPropertyValue("top").replace("px", "")) -
        offsetTop +
        "px";
      pass2.style.left =
        parseFloat(
          window.getComputedStyle(pass2, null).getPropertyValue("left").replace("px", "")
        ) -
        offsetLeft +
        "px";
      pass2.style.width = rect1.width + "px";
      pass2.style.borderRadius = window.getComputedStyle(pass, null).borderRadius;
      window.addEventListener("resize", (event) => {
        rect1 = pass.getBoundingClientRect();
        rect2 = pass2.getBoundingClientRect();
        offsetTop = rect2.top - rect1.top;
        offsetLeft = rect2.left - rect1.left;
        pass2.style.top =
          parseFloat(
            window.getComputedStyle(pass2, null).getPropertyValue("top").replace("px", "")
          ) -
          offsetTop +
          "px";
        pass2.style.left =
          parseFloat(
            window.getComputedStyle(pass2, null).getPropertyValue("left").replace("px", "")
          ) -
          offsetLeft +
          "px";
      });
    }
  }
}
sleep2();
