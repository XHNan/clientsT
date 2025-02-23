import { Location } from "@angular/common";
import { Component } from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";
import { first } from "rxjs/operators";

import { AddEditComponent as BaseAddEditComponent } from "@bitwarden/angular/components/add-edit.component";
import { AuditService } from "@bitwarden/common/abstractions/audit.service";
import { CipherService } from "@bitwarden/common/abstractions/cipher.service";
import { CollectionService } from "@bitwarden/common/abstractions/collection.service";
import { EventService } from "@bitwarden/common/abstractions/event.service";
import { FolderService } from "@bitwarden/common/abstractions/folder/folder.service.abstraction";
import { I18nService } from "@bitwarden/common/abstractions/i18n.service";
import { LogService } from "@bitwarden/common/abstractions/log.service";
import { MessagingService } from "@bitwarden/common/abstractions/messaging.service";
import { OrganizationService } from "@bitwarden/common/abstractions/organization/organization.service.abstraction";
import { PasswordRepromptService } from "@bitwarden/common/abstractions/passwordReprompt.service";
import { PlatformUtilsService } from "@bitwarden/common/abstractions/platformUtils.service";
import { PolicyService } from "@bitwarden/common/abstractions/policy/policy.service.abstraction";
import { StateService } from "@bitwarden/common/abstractions/state.service";
import { CipherType } from "@bitwarden/common/enums/cipherType";
import { LoginUriView } from "@bitwarden/common/models/view/login-uri.view";

import { BrowserApi } from "../../browser/browserApi";
import { PopupUtilsService } from "../services/popup-utils.service";

@Component({
  selector: "app-vault-add-edit",
  templateUrl: "add-edit.component.html",
})
// eslint-disable-next-line rxjs-angular/prefer-takeuntil
export class AddEditComponent extends BaseAddEditComponent {
  currentUris: string[];
  showAttachments = true;
  openAttachmentsInPopup: boolean;
  showAutoFillOnPageLoadOptions: boolean;

  constructor(
    cipherService: CipherService,
    folderService: FolderService,
    i18nService: I18nService,
    platformUtilsService: PlatformUtilsService,
    auditService: AuditService,
    stateService: StateService,
    collectionService: CollectionService,
    messagingService: MessagingService,
    private route: ActivatedRoute,
    private router: Router,
    private location: Location,
    eventService: EventService,
    policyService: PolicyService,
    private popupUtilsService: PopupUtilsService,
    organizationService: OrganizationService,
    passwordRepromptService: PasswordRepromptService,
    logService: LogService
  ) {
    super(
      cipherService,
      folderService,
      i18nService,
      platformUtilsService,
      auditService,
      stateService,
      collectionService,
      messagingService,
      eventService,
      policyService,
      logService,
      passwordRepromptService,
      organizationService
    );

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
              "body > app-root > div > app-vault-add-edit > form > main > div:nth-child(1) > div > div:nth-child(3) > div:nth-child(2) > div.row-main > label"
            ) as HTMLLabelElement
          ).htmlFor = "passwordTemp" + index;
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
              document.getElementById("loginPassword").dispatchEvent(event);
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

    // eslint-disable-next-line rxjs-angular/prefer-takeuntil, rxjs/no-async-subscribe
    this.route.queryParams.pipe(first()).subscribe(async (params) => {
      if (params.cipherId) {
        this.cipherId = params.cipherId;
      }
      if (params.folderId) {
        this.folderId = params.folderId;
      }
      if (params.collectionId) {
        const collection = this.writeableCollections.find((c) => c.id === params.collectionId);
        if (collection != null) {
          this.collectionIds = [collection.id];
          this.organizationId = collection.organizationId;
        }
      }
      if (params.type) {
        const type = parseInt(params.type, null);
        this.type = type;
      }
      this.editMode = !params.cipherId;

      if (params.cloneMode != null) {
        this.cloneMode = params.cloneMode === "true";
      }
      if (params.selectedVault) {
        this.organizationId = params.selectedVault;
      }
      await this.load();

      if (!this.editMode || this.cloneMode) {
        if (
          !this.popupUtilsService.inPopout(window) &&
          params.name &&
          (this.cipher.name == null || this.cipher.name === "")
        ) {
          this.cipher.name = params.name;
        }
        if (
          !this.popupUtilsService.inPopout(window) &&
          params.uri &&
          (this.cipher.login.uris[0].uri == null || this.cipher.login.uris[0].uri === "")
        ) {
          this.cipher.login.uris[0].uri = params.uri;
        }
      }

      this.openAttachmentsInPopup = this.popupUtilsService.inPopup(window);
    });

    if (!this.editMode) {
      const tabs = await BrowserApi.tabsQuery({ windowType: "normal" });
      this.currentUris =
        tabs == null
          ? null
          : tabs.filter((tab) => tab.url != null && tab.url !== "").map((tab) => tab.url);
    }

    window.setTimeout(() => {
      if (!this.editMode) {
        if (this.cipher.name != null && this.cipher.name !== "") {
          document.getElementById("loginUsername").focus();
        } else {
          document.getElementById("name").focus();
        }
      }
    }, 200);
  }

  async load() {
    await super.load();
    this.showAutoFillOnPageLoadOptions =
      this.cipher.type === CipherType.Login &&
      (await this.stateService.getEnableAutoFillOnPageLoad());
  }

  async submit(): Promise<boolean> {
    if (await super.submit()) {
      if (this.cloneMode) {
        this.router.navigate(["/tabs/vault"]);
      } else {
        this.location.back();
      }
      return true;
    }

    return false;
  }

  attachments() {
    super.attachments();

    if (this.openAttachmentsInPopup) {
      const destinationUrl = this.router
        .createUrlTree(["/attachments"], { queryParams: { cipherId: this.cipher.id } })
        .toString();
      const currentBaseUrl = window.location.href.replace(this.router.url, "");
      this.popupUtilsService.popOut(window, currentBaseUrl + destinationUrl);
    } else {
      this.router.navigate(["/attachments"], { queryParams: { cipherId: this.cipher.id } });
    }
  }

  editCollections() {
    super.editCollections();
    if (this.cipher.organizationId != null) {
      this.router.navigate(["/collections"], { queryParams: { cipherId: this.cipher.id } });
    }
  }

  cancel() {
    super.cancel();
    this.location.back();
  }

  async generateUsername(): Promise<boolean> {
    const confirmed = await super.generateUsername();
    if (confirmed) {
      await this.saveCipherState();
      this.router.navigate(["generator"], { queryParams: { type: "username" } });
    }
    return confirmed;
  }

  async generatePassword(): Promise<boolean> {
    const confirmed = await super.generatePassword();
    if (confirmed) {
      await this.saveCipherState();
      this.router.navigate(["generator"], { queryParams: { type: "password" } });
    }
    return confirmed;
  }

  async delete(): Promise<boolean> {
    const confirmed = await super.delete();
    if (confirmed) {
      this.router.navigate(["/tabs/vault"]);
    }
    return confirmed;
  }

  toggleUriInput(uri: LoginUriView) {
    const u = uri as any;
    u.showCurrentUris = !u.showCurrentUris;
  }

  allowOwnershipOptions(): boolean {
    return (
      (!this.editMode || this.cloneMode) &&
      this.ownershipOptions &&
      (this.ownershipOptions.length > 1 || !this.allowPersonal)
    );
  }

  private saveCipherState() {
    return this.stateService.setAddEditCipherInfo({
      cipher: this.cipher,
      collectionIds:
        this.collections == null
          ? []
          : this.collections.filter((c) => (c as any).checked).map((c) => c.id),
    });
  }
}
