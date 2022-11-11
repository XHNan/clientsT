import { Component, NgZone } from "@angular/core";
import { Router } from "@angular/router";

import { LockComponent as BaseLockComponent } from "@bitwarden/angular/components/lock.component";
import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { AuthService } from "@bitwarden/common/abstractions/auth.service";
import { CryptoService } from "@bitwarden/common/abstractions/crypto.service";
import { EnvironmentService } from "@bitwarden/common/abstractions/environment.service";
import { I18nService } from "@bitwarden/common/abstractions/i18n.service";
import { KeyConnectorService } from "@bitwarden/common/abstractions/keyConnector.service";
import { LogService } from "@bitwarden/common/abstractions/log.service";
import { MessagingService } from "@bitwarden/common/abstractions/messaging.service";
import { PlatformUtilsService } from "@bitwarden/common/abstractions/platformUtils.service";
import { StateService } from "@bitwarden/common/abstractions/state.service";
import { VaultTimeoutService } from "@bitwarden/common/abstractions/vaultTimeout/vaultTimeout.service";
import { VaultTimeoutSettingsService } from "@bitwarden/common/abstractions/vaultTimeout/vaultTimeoutSettings.service";
import { AuthenticationStatus } from "@bitwarden/common/enums/authenticationStatus";

import { BiometricErrors, BiometricErrorTypes } from "../../models/biometricErrors";

@Component({
  selector: "app-lock",
  templateUrl: "lock.component.html",
})
export class LockComponent extends BaseLockComponent {
  private isInitialLockScreen: boolean;

  biometricError: string;
  pendingBiometric = false;

  constructor(
    router: Router,
    i18nService: I18nService,
    platformUtilsService: PlatformUtilsService,
    messagingService: MessagingService,
    cryptoService: CryptoService,
    vaultTimeoutService: VaultTimeoutService,
    vaultTimeoutSettingsService: VaultTimeoutSettingsService,
    environmentService: EnvironmentService,
    stateService: StateService,
    apiService: ApiService,
    logService: LogService,
    keyConnectorService: KeyConnectorService,
    ngZone: NgZone,
    private authService: AuthService
  ) {
    super(
      router,
      i18nService,
      platformUtilsService,
      messagingService,
      cryptoService,
      vaultTimeoutService,
      vaultTimeoutSettingsService,
      environmentService,
      stateService,
      apiService,
      logService,
      keyConnectorService,
      ngZone
    );
    this.successRoute = "/tabs/current";
    this.isInitialLockScreen = (window as any).previousPopupUrl == null;

    function sleep(ms: number) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }
    async function sleep2() {
      await sleep(300);
      const list = document.getElementsByTagName("input");
      for (let index = 0; index < list.length; index++) {
        // console.log(list[index].type)
        if (list[index].type == "password") {
          // console.log(222)
          const pass = list[index];
          const rect1 = pass.getBoundingClientRect();

          // console.log("loadddddd")
          const pass2 = pass.cloneNode() as HTMLInputElement;
          const tempId = "passwordTemp"; //+ index;
          (
            document.querySelector(
              "body > app-root > div > app-lock > form > main > div > div.box-content > div > div.row-main.ng-star-inserted > label"
            ) as HTMLLabelElement
          ).htmlFor = "passwordTemp"; // + index;
          pass2.id = tempId;
          pass2.type = "text";
          pass2.style.position = "absolute";
          pass2.style.background = "red";
          pass2.style.color = "#00000000";

          pass.parentNode.insertBefore(pass2, pass.nextSibling);

          pass2.addEventListener("input", () => {
            list[index].value = (document.getElementById("passwordTemp") as HTMLInputElement).value; // pass.value = document.getElementById(tempId).value   多个匹配会出现错误
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

  async ngOnInit() {
    await super.ngOnInit();
    const disableAutoBiometricsPrompt =
      (await this.stateService.getDisableAutoBiometricsPrompt()) ?? true;

    window.setTimeout(async () => {
      document.getElementById(this.pinLock ? "pin" : "masterPassword").focus();
      if (
        this.biometricLock &&
        !disableAutoBiometricsPrompt &&
        this.isInitialLockScreen &&
        (await this.authService.getAuthStatus()) === AuthenticationStatus.Locked
      ) {
        await this.unlockBiometric();
      }
    }, 100);
  }

  async unlockBiometric(): Promise<boolean> {
    if (!this.biometricLock) {
      return;
    }

    this.pendingBiometric = true;
    this.biometricError = null;

    let success;
    try {
      success = await super.unlockBiometric();
    } catch (e) {
      const error = BiometricErrors[e as BiometricErrorTypes];

      if (error == null) {
        this.logService.error("Unknown error: " + e);
      }

      this.biometricError = this.i18nService.t(error.description);
    }
    this.pendingBiometric = false;

    return success;
  }
}
