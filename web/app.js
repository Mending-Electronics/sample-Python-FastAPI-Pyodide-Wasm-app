const SOURCE_FILES = [
  "backend/vba_audit/analyzer.py",
  "backend/vba_audit/database.py",
  "backend/vba_audit/api.py",
  "backend/vba_audit/__init__.py",
];
const DATABASE_NAME = "vba-audit-local";
const DATABASE_KEY = "reports";
const PYODIDE_BASE = "/vendor/pyodide/";

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("state");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function readDatabase(db) {
  return new Promise((resolve, reject) => {
    const request = db.transaction("state", "readonly").objectStore("state").get(DATABASE_KEY);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

function writeDatabase(db, value) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("state", "readwrite");
    transaction.objectStore("state").put(value, DATABASE_KEY);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error || new Error("Échec de sauvegarde SQLite."));
  });
}

function decodeBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

Vue.createApp({
  data() {
    return {
      ready: false,
      busy: false,
      error: "",
      statusText: "Chargement de Python WASM…",
      selectedFile: null,
      sourceText: "",
      report: null,
      reports: [],
      pyodide: null,
      browserDatabase: null,
    };
  },
  computed: {
    canAnalyze() {
      return this.ready && !this.busy && (
        (this.selectedFile && this.selectedFile.name) || this.sourceText.trim()
      );
    },
  },
  async mounted() {
    let stage = "ouverture du stockage IndexedDB";
    try {
      this.browserDatabase = Vue.markRaw(await openDatabase());
      stage = "chargement de Pyodide";
      this.pyodide = Vue.markRaw(await loadPyodide({ indexURL: PYODIDE_BASE }));
      stage = "chargement du moteur Python";
      await this.loadPythonSources();
      stage = "restauration de SQLite";
      const saved = await readDatabase(this.browserDatabase);
      if (saved) {
        this.pyodide.globals.set("_database_snapshot", bytesToBase64(saved));
        await this.pyodide.runPythonAsync("_restore_database_base64(_database_snapshot)");
      }
      stage = "lecture des rapports";
      await this.refreshReports();
      this.ready = true;
      this.statusText = "Moteur local prêt";
    } catch (error) {
      this.error = `Impossible d’initialiser le moteur local (${stage}) : ${error.message}`;
      this.statusText = "Initialisation échouée";
    }
  },
  methods: {
    async loadPythonSources() {
      const modules = await Promise.all(SOURCE_FILES.map(async (path) => {
        const response = await fetch(`/${path}`, { cache: "no-store" });
        if (!response.ok) {
          throw new Error(`Chargement impossible : ${path} (${response.status}).`);
        }
        return [path, await response.text()];
      }));
      this.pyodide.FS.mkdirTree("/home/pyodide/backend/vba_audit");
      for (const [path, source] of modules) {
        const relative = path.replace("backend/", "");
        this.pyodide.FS.writeFile(`/home/pyodide/backend/${relative}`, source);
      }
      await this.pyodide.runPythonAsync(`
import sys
sys.path.insert(0, "/home/pyodide/backend")
from vba_audit.api import (
    create_api,
)
api = create_api()

def _analyze_source_json(filename, source):
    return api.analyze_source_json(filename, source)

def _analyze_workbook_path_json(filename, path):
    return api.analyze_workbook_path_json(filename, path)

def _report_list_json():
    return api.reports_json()

def _report_json(report_id):
    return api.report_json(report_id)

def _export_database_base64():
    return api.database_base64()

def _restore_database_base64(value):
    return api.restore_database_base64(value)
      `);
    },
    selectFile(event) {
      this.selectedFile = Vue.markRaw(event.target.files?.[0] || null);
      this.sourceText = "";
      this.report = null;
      this.error = "";
    },
    async analyze() {
      if (!this.canAnalyze) return;
      this.busy = true;
      this.error = "";
      this.report = null;
      try {
        let response;
        if (this.selectedFile) {
          const extension = this.selectedFile.name.split(".").pop().toLowerCase();
          if (extension === "xlsx" || extension === "xlsm") {
            if (this.selectedFile.size > 50 * 1024 * 1024) {
              throw new Error("Le classeur dépasse la limite de 50 Mio.");
            }
            const bytes = new Uint8Array(await this.selectedFile.arrayBuffer());
            this.pyodide.FS.writeFile("/tmp/workbook-upload", bytes);
            this.pyodide.globals.set("_upload_filename", this.selectedFile.name);
            response = await this.pyodide.runPythonAsync(
              "_analyze_workbook_path_json(_upload_filename, '/tmp/workbook-upload')",
            );
          } else {
            if (!["bas", "cls", "frm", "vba", "txt"].includes(extension)) {
              throw new Error("Format refusé. Sélectionnez un module VBA exporté.");
            }
            if (this.selectedFile.size > 2 * 1024 * 1024) {
              throw new Error("Le fichier VBA dépasse la limite de 2 Mio.");
            }
            const source = await this.selectedFile.text();
            this.pyodide.globals.set("_upload_filename", this.selectedFile.name);
            this.pyodide.globals.set("_upload_source", source);
            response = await this.pyodide.runPythonAsync(
              "_analyze_source_json(_upload_filename, _upload_source)",
            );
          }
        } else {
          this.pyodide.globals.set("_upload_filename", "module-colle.bas");
          this.pyodide.globals.set("_upload_source", this.sourceText);
          response = await this.pyodide.runPythonAsync(
            "_analyze_source_json(_upload_filename, _upload_source)",
          );
        }
        this.report = JSON.parse(response);
        await this.persistDatabase();
        await this.refreshReports();
      } catch (error) {
        this.error = `Analyse impossible : ${error.message}`;
      } finally {
        this.busy = false;
      }
    },
    async persistDatabase() {
      const encoded = await this.pyodide.runPythonAsync("_export_database_base64()");
      await writeDatabase(this.browserDatabase, decodeBase64(encoded));
    },
    async refreshReports() {
      this.reports = JSON.parse(await this.pyodide.runPythonAsync("_report_list_json()"));
    },
    async openReport(reportId) {
      this.pyodide.globals.set("_report_id", reportId);
      this.report = JSON.parse(await this.pyodide.runPythonAsync("_report_json(_report_id)"));
      this.error = "";
    },
    riskClass(risk) {
      return `badge-risk-${risk}`;
    },
    severityClass(severity) {
      return `badge-severity-${severity}`;
    },
    formatDate(value) {
      return new Intl.DateTimeFormat("fr-FR", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(new Date(value));
    },
    downloadReport() {
      const blob = new Blob([JSON.stringify(this.report, null, 2)], {
        type: "application/json",
      });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `rapport-vba-${this.report.id}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
    },
  },
}).mount("#app");
