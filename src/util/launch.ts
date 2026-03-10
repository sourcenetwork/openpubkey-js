import { execFile, spawn } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * Opens the specified URL in the user's default browser.
 * Cross-platform: macOS (open), Linux (xdg-open), Windows (start).
 * Uses execFile with argument arrays to prevent command injection.
 */
export async function openUrl(url: string): Promise<void> {
  const platform = process.platform;
  try {
    switch (platform) {
      case 'win32':
        await execFileAsync('cmd.exe', ['/c', 'start', '', url]);
        break;
      case 'darwin':
        await execFileAsync('open', [url]);
        break;
      default:
        await execFileAsync('xdg-open', [url]);
        break;
    }
  } catch (error) {
    throw new Error(`Failed to open URL in browser: ${error}`);
  }
}

/**
 * Non-blocking version of openUrl that doesn't wait for the browser to open.
 */
export function openUrlSync(url: string): void {
  const platform = process.platform;
  let command: string;
  let args: string[];
  switch (platform) {
    case 'win32':
      command = 'cmd.exe';
      args = ['/c', 'start', '', url];
      break;
    case 'darwin':
      command = 'open';
      args = [url];
      break;
    default:
      command = 'xdg-open';
      args = [url];
      break;
  }
  const child = spawn(command, args, {
    detached: true,
    stdio: 'ignore',
  });
  child.on('error', () => {
    // Silently ignore errors from detached browser process
  });
  child.unref();
}
