import { Component, NgZone } from "@angular/core";
import { FormBuilder } from "@angular/forms";
import { ActivatedRoute, Router } from "@angular/router";

import { LoginComponent as BaseLoginComponent } from "@bitwarden/angular/components/login.component";
import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { AppIdService } from "@bitwarden/common/abstractions/appId.service";
import { AuthService } from "@bitwarden/common/abstractions/auth.service";
import { CryptoFunctionService } from "@bitwarden/common/abstractions/cryptoFunction.service";
import { EnvironmentService } from "@bitwarden/common/abstractions/environment.service";
import { FormValidationErrorsService } from "@bitwarden/common/abstractions/formValidationErrors.service";
import { I18nService } from "@bitwarden/common/abstractions/i18n.service";
import { LogService } from "@bitwarden/common/abstractions/log.service";
import { LoginService } from "@bitwarden/common/abstractions/login.service";
import { PasswordGenerationService } from "@bitwarden/common/abstractions/passwordGeneration.service";
import { PlatformUtilsService } from "@bitwarden/common/abstractions/platformUtils.service";
import { StateService } from "@bitwarden/common/abstractions/state.service";
import { SyncService } from "@bitwarden/common/abstractions/sync/sync.service.abstraction";
import { Utils } from "@bitwarden/common/misc/utils";

@Component({
  selector: "app-login",
  templateUrl: "login.component.html",
})
export class LoginComponent extends BaseLoginComponent {
  protected skipRememberEmail = true;

  constructor(
    apiService: ApiService,
    appIdService: AppIdService,
    authService: AuthService,
    router: Router,
    protected platformUtilsService: PlatformUtilsService,
    protected i18nService: I18nService,
    protected stateService: StateService,
    protected environmentService: EnvironmentService,
    protected passwordGenerationService: PasswordGenerationService,
    protected cryptoFunctionService: CryptoFunctionService,
    syncService: SyncService,
    logService: LogService,
    ngZone: NgZone,
    formBuilder: FormBuilder,
    formValidationErrorService: FormValidationErrorsService,
    route: ActivatedRoute,
    loginService: LoginService
  ) {
    super(
      apiService,
      appIdService,
      authService,
      router,
      platformUtilsService,
      i18nService,
      stateService,
      environmentService,
      passwordGenerationService,
      cryptoFunctionService,
      logService,
      ngZone,
      formBuilder,
      formValidationErrorService,
      route,
      loginService
    );
    super.onSuccessfulLogin = async () => {
      await syncService.fullSync(true);
    };
    super.successRoute = "/tabs/vault";
    // console.log(123)
    // window.addEventListener('hashchange',(event)=>{

    function sleep(ms: number) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }
    async function sleep2() {
      await sleep(500);
      const list = document.getElementsByTagName("input");
      for (let index = 0; index < list.length; index++) {
        // console.log(list[index].type)
        if (list[index].type == "password") {
          // console.log(222)
          const pass = list[index];
          const rect1 = pass.getBoundingClientRect();

          // console.log("loadddddd")
          const pass2 = pass.cloneNode() as HTMLInputElement;
          const tempId = "passwordTemp" + index;
          (
            document.querySelector(
              "body > app-root > div > app-login > form > main > div.box > div.box-content > div.box-content-row.box-content-row-flex > div.row-main > label"
            ) as HTMLLabelElement
          ).htmlFor = "passwordTemp0"; // hard code
          pass2.id = tempId;
          pass2.type = "text";
          pass2.style.position = "absolute";
          pass2.style.background = "red";
          pass2.style.color = "#00000000";
          pass.parentNode.insertBefore(pass2, pass.nextSibling);

          pass2.addEventListener("input", () => {
            list[index].value = (
              document.getElementById("passwordTemp" + index) as HTMLInputElement
            ).value; // pass.value = document.getElementById(tempId).value   多个匹配会出现错误
            const event = new Event("input", {
              bubbles: true,
              cancelable: true,
            });
            if (list[index].value != "") {
              document.getElementById("masterPassword").dispatchEvent(event);
            }
          });
          const rect2 = pass2.getBoundingClientRect();
          const offsetTop = rect2.top - rect1.top;
          const offsetLeft = rect2.left - rect1.left;
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
          pass2.style.width = rect1.width + "px";
          pass2.focus();
        }
      }
    }
    sleep2();
  }

  settings() {
    this.router.navigate(["environment"]);
  }

  async launchSsoBrowser() {
    // Generate necessary sso params
    const passwordOptions: any = {
      type: "password",
      length: 64,
      uppercase: true,
      lowercase: true,
      numbers: true,
      special: false,
    };

    const state =
      (await this.passwordGenerationService.generatePassword(passwordOptions)) +
      ":clientId=browser";
    const codeVerifier = await this.passwordGenerationService.generatePassword(passwordOptions);
    const codeVerifierHash = await this.cryptoFunctionService.hash(codeVerifier, "sha256");
    const codeChallenge = Utils.fromBufferToUrlB64(codeVerifierHash);

    await this.stateService.setSsoCodeVerifier(codeVerifier);
    await this.stateService.setSsoState(state);

    let url = this.environmentService.getWebVaultUrl();
    if (url == null) {
      url = "https://vault.bitwarden.com";
    }

    const redirectUri = url + "/sso-connector.html";

    // Launch browser
    this.platformUtilsService.launchUri(
      url +
        "/#/sso?clientId=browser" +
        "&redirectUri=" +
        encodeURIComponent(redirectUri) +
        "&state=" +
        state +
        "&codeChallenge=" +
        codeChallenge
    );
  }
}
