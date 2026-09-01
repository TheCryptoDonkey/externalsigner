window.app = Vue.createApp({
  el: "#vue",
  mixins: [windowMixin],
  data() {
    return {
      loading: true,
      connections: [],
      presets: [],
      activeOperation: null,
      operationTimer: null,
      connectionTimer: null,
      clockTimer: null,
      clockNow: Date.now(),
      showRevoked: false,
      pollFailureNotified: false,
      bunkerDialog: {
        show: false,
        loading: false,
        name: "",
        uri: "",
        preset: "identity",
        permissions: "",
      },
      qrDialog: {
        show: false,
        loading: false,
        name: "",
        relays: "wss://relay.nostrconnect.com",
        preset: "identity",
        permissions: "",
      },
    };
  },
  computed: {
    presetOptions() {
      return this.presets.map((preset) => ({
        label: preset.name,
        value: preset.id,
        description: preset.description,
      }));
    },
    activeConnections() {
      return this.connections.filter(
        (connection) => connection.status !== "revoked",
      );
    },
    revokedConnections() {
      return this.connections.filter(
        (connection) => connection.status === "revoked",
      );
    },
  },
  methods: {
    permissionsFor(presetId) {
      const preset = this.presets.find((item) => item.id === presetId);
      return preset ? preset.permissions.join(", ") : "";
    },
    presetDescription(presetId) {
      const preset = this.presets.find((item) => item.id === presetId);
      return preset
        ? preset.description
        : "Choose the smallest scope that fits your use.";
    },
    applyBunkerPreset(value) {
      this.bunkerDialog.permissions = this.permissionsFor(value);
    },
    applyQrPreset(value) {
      this.qrDialog.permissions = this.permissionsFor(value);
    },
    parsePermissions(value) {
      return value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
    },
    parseRelays(value) {
      return value
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean);
    },
    async loadPresets() {
      const response = await LNbits.api.request(
        "GET",
        "/externalsigner/api/v1/presets",
        null,
      );
      this.presets = response.data;
      this.applyBunkerPreset(this.bunkerDialog.preset);
      this.applyQrPreset(this.qrDialog.preset);
    },
    async loadConnections(silent = false) {
      if (!silent) this.loading = true;
      try {
        const response = await LNbits.api.request(
          "GET",
          "/externalsigner/api/v1/connections",
          null,
        );
        this.connections = response.data;
        this.pollFailureNotified = false;
      } catch (error) {
        if (!silent || !this.pollFailureNotified) {
          LNbits.utils.notifyApiError(error);
          this.pollFailureNotified = true;
        }
      } finally {
        this.loading = false;
      }
    },
    showBunkerDialog() {
      this.applyBunkerPreset(this.bunkerDialog.preset);
      this.bunkerDialog.show = true;
    },
    showQrDialog() {
      this.applyQrPreset(this.qrDialog.preset);
      this.qrDialog.show = true;
    },
    async createBunkerConnection() {
      this.bunkerDialog.loading = true;
      try {
        const response = await LNbits.api.request(
          "POST",
          "/externalsigner/api/v1/connections/bunker",
          null,
          {
            name: this.bunkerDialog.name,
            bunker_uri: this.bunkerDialog.uri,
            permissions: this.parsePermissions(this.bunkerDialog.permissions),
          },
        );
        this.activeOperation = response.data.operation;
        this.watchOperation(this.activeOperation);
        this.bunkerDialog.show = false;
        this.bunkerDialog.name = "";
        this.bunkerDialog.uri = "";
        await this.loadConnections(true);
      } catch (error) {
        LNbits.utils.notifyApiError(error);
      } finally {
        this.bunkerDialog.loading = false;
      }
    },
    async createNostrConnectConnection() {
      this.qrDialog.loading = true;
      try {
        await LNbits.api.request(
          "POST",
          "/externalsigner/api/v1/connections/nostrconnect",
          null,
          {
            name: this.qrDialog.name,
            relays: this.parseRelays(this.qrDialog.relays),
            permissions: this.parsePermissions(this.qrDialog.permissions),
          },
        );
        this.qrDialog.show = false;
        this.qrDialog.name = "";
        await this.loadConnections(true);
      } catch (error) {
        LNbits.utils.notifyApiError(error);
      } finally {
        this.qrDialog.loading = false;
      }
    },
    async ping(connection) {
      try {
        const response = await LNbits.api.request(
          "POST",
          `/externalsigner/api/v1/connections/${connection.id}/requests`,
          null,
          { method: "ping", params: [] },
        );
        this.activeOperation = response.data;
        this.watchOperation(response.data);
      } catch (error) {
        LNbits.utils.notifyApiError(error);
      }
    },
    async retry(connection) {
      try {
        const response = await LNbits.api.request(
          "POST",
          `/externalsigner/api/v1/connections/${connection.id}/retry`,
          null,
          {},
        );
        if (response.data.operation) {
          this.activeOperation = response.data.operation;
          this.watchOperation(response.data.operation);
        }
        await this.loadConnections(true);
      } catch (error) {
        LNbits.utils.notifyApiError(error);
      }
    },
    revoke(connection) {
      LNbits.utils
        .confirmDialog(
          `Revoke ${connection.name}? LNbits will erase its local client capability and request signer-side logout. You should also remove this client in the signer.`,
        )
        .onOk(async () => {
          try {
            await LNbits.api.request(
              "DELETE",
              `/externalsigner/api/v1/connections/${connection.id}`,
              null,
            );
            await this.loadConnections(true);
            Quasar.Notify.create({
              type: "positive",
              message:
                "Connection revoked locally. Revoke it in the signer too.",
            });
          } catch (error) {
            LNbits.utils.notifyApiError(error);
          }
        });
    },
    watchOperation(operation) {
      if (!operation) return;
      if (this.operationTimer) clearInterval(this.operationTimer);
      if (["complete", "failed"].includes(operation.status)) return;
      this.operationTimer = setInterval(async () => {
        try {
          const response = await LNbits.api.request(
            "GET",
            `/externalsigner/api/v1/operations/${operation.id}`,
            null,
          );
          this.activeOperation = response.data;
          await this.loadConnections(true);
          if (["complete", "failed"].includes(response.data.status)) {
            clearInterval(this.operationTimer);
            this.operationTimer = null;
            Quasar.Notify.create({
              type:
                response.data.status === "complete" ? "positive" : "negative",
              message:
                response.data.status === "complete"
                  ? "Signer request completed"
                  : "Signer request failed",
            });
          }
        } catch (error) {
          clearInterval(this.operationTimer);
          this.operationTimer = null;
          LNbits.utils.notifyApiError(error);
        }
      }, 1500);
    },
    statusColor(status) {
      return (
        {
          connected: "positive",
          error: "negative",
          revoked: "grey",
          awaiting_signer: "amber-9",
          connecting: "blue",
          verifying: "purple",
        }[status] || "grey"
      );
    },
    statusIcon(status) {
      return (
        {
          connected: "verified_user",
          error: "error_outline",
          revoked: "link_off",
          awaiting_signer: "qr_code_scanner",
          connecting: "send",
          verifying: "fact_check",
        }[status] || "schedule"
      );
    },
    statusLabel(status) {
      const words = status.replaceAll("_", " ");
      return words.charAt(0).toUpperCase() + words.slice(1);
    },
    statusHelp(connection) {
      return (
        {
          connected: "Identity verified. Ready for approved requests.",
          error: "Connection needs attention. Read the error and retry.",
          revoked: "The local client capability has been erased.",
          awaiting_signer: "Waiting for the signer to scan and approve the QR.",
          connecting:
            "Invite sent. Open the signer and approve the connection.",
          verifying: "Signer answered. Verifying the user identity now.",
        }[connection.status] || "Waiting for the next signer response."
      );
    },
    statusBannerClass(status) {
      return (
        {
          connected: "bg-green-1 text-green-10",
          error: "bg-red-1 text-red-10",
          revoked: "bg-grey-2 text-grey-9",
          awaiting_signer: "bg-amber-1 text-amber-10",
          connecting: "bg-blue-1 text-blue-10",
          verifying: "bg-purple-1 text-purple-10",
        }[status] || "bg-blue-grey-1 text-blue-grey-10"
      );
    },
    shortKey(value) {
      if (!value) return "Waiting for identity";
      return `${value.slice(0, 12)}…${value.slice(-8)}`;
    },
    modeLabel(mode) {
      return mode === "bunker"
        ? "Signer-provided bunker invite"
        : "LNbits pairing QR";
    },
    formatDate(value) {
      return value ? new Date(value).toLocaleString() : "Not proved yet";
    },
    pairingTimeRemaining(connection) {
      if (!connection.pairing_expires_at) return "no active expiry";
      const seconds = Math.max(
        0,
        Math.ceil(
          (new Date(connection.pairing_expires_at).getTime() - this.clockNow) /
            1000,
        ),
      );
      if (!seconds) return "expired";
      const minutes = Math.floor(seconds / 60);
      return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
    },
    methodLabel(method) {
      return (
        {
          connect: "Connect signer",
          get_public_key: "Read user public key",
          sign_event: "Sign event",
          switch_relays: "Check signer relays",
          ping: "Test connection",
          nip04_encrypt: "NIP-04 encrypt",
          nip04_decrypt: "NIP-04 decrypt",
          nip44_encrypt: "NIP-44 encrypt",
          nip44_decrypt: "NIP-44 decrypt",
        }[method] || method
      );
    },
    operationColor(status) {
      return (
        {
          complete: "positive",
          failed: "negative",
          auth_required: "amber-9",
          processing: "purple",
          sent: "blue",
          pending: "grey-7",
        }[status] || "grey"
      );
    },
    operationStatusLabel(status) {
      return this.statusLabel(status);
    },
    operationHelp(operation) {
      return (
        {
          pending: "Preparing the encrypted request.",
          sent: "Sent through the selected relay. Waiting for the signer.",
          processing: "Authenticating and storing the signer response.",
          auth_required:
            "The signer needs a separate approval before it can answer.",
          complete: "The signer returned a final response.",
          failed: "The request did not complete. Read the error below.",
        }[operation.status] || "Waiting for the signer."
      );
    },
    formatResult(value) {
      return typeof value === "string" ? value : JSON.stringify(value, null, 2);
    },
    async copy(value, message = "Copied") {
      try {
        await Quasar.copyToClipboard(value);
        Quasar.Notify.create({ type: "positive", message });
      } catch (_) {
        Quasar.Notify.create({ type: "negative", message: "Copy failed" });
      }
    },
  },
  async created() {
    try {
      await this.loadPresets();
      await this.loadConnections();
      this.connectionTimer = setInterval(
        () => this.loadConnections(true),
        3000,
      );
      this.clockTimer = setInterval(() => {
        this.clockNow = Date.now();
      }, 1000);
    } catch (error) {
      this.loading = false;
      LNbits.utils.notifyApiError(error);
    }
  },
  beforeUnmount() {
    if (this.operationTimer) clearInterval(this.operationTimer);
    if (this.connectionTimer) clearInterval(this.connectionTimer);
    if (this.clockTimer) clearInterval(this.clockTimer);
  },
});
