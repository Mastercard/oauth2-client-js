import { rmSync } from 'fs';
import { spawn } from 'child_process';
import pkg from '../../package.json' with { type: 'json' };

const clientScripts = Object.keys(pkg.scripts).filter(s => s.startsWith('generate-clients:'));

rmSync('tests/generated-clients', { recursive: true, force: true });

for (const script of clientScripts) {
  await new Promise((resolve, reject) => {
    const child = spawn('npm', ['run', script], { stdio: 'inherit', shell: true });
    child.on('exit', code => (code === 0 ? resolve() : reject(new Error(`Script ${script} failed with code ${code}`))));
  });
}
