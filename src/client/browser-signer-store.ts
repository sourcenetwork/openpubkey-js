const DB_NAME = 'openpubkey-browser';
const STORE_NAME = 'oauth-signers';
const DB_VERSION = 1;

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    let blocked = false;
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onblocked = () => {
      blocked = true;
      reject(new Error('Browser signer database upgrade blocked by another tab'));
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => db.close();
      if (blocked) {
        db.close();
        return;
      }
      resolve(db);
    };
    request.onerror = () => reject(request.error);
  });
}

function assertNonExtractableSigner(signer: CryptoKey): void {
  if (signer.type !== 'private' || signer.extractable || !signer.usages.includes('sign')) {
    throw new Error('Browser signer must be a non-extractable private signing key');
  }
}

export async function saveBrowserSigner(id: string, signer: CryptoKey): Promise<void> {
  if (!id) {
    throw new Error('Browser signer ID is required');
  }
  assertNonExtractableSigner(signer);

  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(signer, id);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error);
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error);
    };
  });
}

export async function loadBrowserSigner(id: string): Promise<CryptoKey | null> {
  if (!id) {
    return null;
  }

  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).get(id);
    request.onsuccess = () => {
      const signer = request.result as CryptoKey | undefined;
      if (signer) {
        try {
          assertNonExtractableSigner(signer);
        } catch (error) {
          db.close();
          reject(error);
          return;
        }
      }
      db.close();
      resolve(signer ?? null);
    };
    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

export async function deleteBrowserSigner(id: string): Promise<void> {
  if (!id) {
    return;
  }

  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(id);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error);
    };
    tx.onabort = () => {
      db.close();
      reject(tx.error);
    };
  });
}
