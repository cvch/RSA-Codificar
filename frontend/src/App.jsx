import { useMemo, useState } from 'react';
import { generateKeys, selectE, encrypt, decrypt } from './api';
import KeyCard from './components/KeyCard';
import ConsolePanel from './components/ConsolePanel';
import Stepper from './components/Stepper';
import CipherFlow from './components/CipherFlow';

const STEPS = ['Primos', 'Elegir e', 'Cifrar', 'Descifrar'];

export default function App() {
  const [step, setStep] = useState(0);

  const [p, setP] = useState('');
  const [q, setQ] = useState('');
  const [eSeleccionado, setESeleccionado] = useState('');
  const [mensaje, setMensaje] = useState('');

  const [valoresE, setValoresE] = useState([]);
  const [tablaMcd, setTablaMcd] = useState([]);
  const [n, setN] = useState(null);
  const [phi, setPhi] = useState(null);
  const [d, setD] = useState(null);
  const [publicKey, setPublicKey] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);

  const [cipher, setCipher] = useState([]);
  const [cipherText, setCipherText] = useState('');
  const [mensajeDescifrado, setMensajeDescifrado] = useState('');

  const [consola, setConsola] = useState([]);
  const [errores, setErrores] = useState([]);
  const [loading, setLoading] = useState(false);

  const appendConsole = (lineas) =>
    setConsola((prev) => [...prev, ...lineas]);

  const resetAll = () => {
    setP(''); setQ(''); setESeleccionado(''); setMensaje('');
    setValoresE([]); setTablaMcd([]); setN(null); setPhi(null); setD(null);
    setPublicKey(null); setPrivateKey(null);
    setCipher([]); setCipherText(''); setMensajeDescifrado('');
    setConsola([]); setErrores([]); setStep(0);
  };

  const handleGenerar = async () => {
    setErrores([]);
    setLoading(true);
    try {
      const res = await generateKeys(Number(p), Number(q));
      if (!res.success) { setErrores(res.errors); return; }
      setN(res.n); setPhi(res.phi);
      setValoresE(res.valores_e);
      setTablaMcd(res.tabla_mcd || []);
      setESeleccionado(''); setD(null);
      setPublicKey(null); setPrivateKey(null);
      setCipher([]); setCipherText(''); setMensajeDescifrado('');
      appendConsole(['── Generación de claves ──', ...res.pasos]);
      setStep(1);
    } catch (err) {
      setErrores([`Error de conexión: ${err.message}`]);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectE = async () => {
    setErrores([]);
    if (!eSeleccionado) { setErrores(['Selecciona un valor de e.']); return; }
    setLoading(true);
    try {
      const res = await selectE(Number(p), Number(q), Number(eSeleccionado));
      if (!res.success) { setErrores(res.errors); return; }
      setD(res.d);
      setPublicKey(res.public_key);
      setPrivateKey(res.private_key);
      appendConsole(['── Cálculo de d ──', ...res.pasos]);
      setStep(2);
    } catch (err) {
      setErrores([`Error de conexión: ${err.message}`]);
    } finally {
      setLoading(false);
    }
  };

  const handleCifrar = async () => {
    setErrores([]);
    if (!mensaje) { setErrores(['Escribe un mensaje para cifrar.']); return; }
    if (!publicKey) { setErrores(['Primero genera las claves.']); return; }
    setLoading(true);
    try {
      const res = await encrypt(mensaje, publicKey.e, publicKey.n);
      if (!res.success) { setErrores(res.errors); return; }
      setCipher(res.cipher);
      setCipherText(res.cipher_text);
      setMensajeDescifrado('');
      appendConsole(['── Cifrado ──', ...res.pasos]);
      setStep(3);
    } catch (err) {
      setErrores([`Error de conexión: ${err.message}`]);
    } finally {
      setLoading(false);
    }
  };

  const handleDescifrar = async () => {
    setErrores([]);
    if (!cipher.length) { setErrores(['Primero cifra un mensaje.']); return; }
    setLoading(true);
    try {
      const res = await decrypt(cipher, privateKey.d, privateKey.n);
      if (!res.success) { setErrores(res.errors || ['No se pudo descifrar.']); return; }
      setMensajeDescifrado(res.message);
      appendConsole(['── Descifrado ──', ...res.pasos]);
    } catch (err) {
      setErrores([`Error de conexión: ${err.message}`]);
    } finally {
      setLoading(false);
    }
  };

  const coprimosCount = useMemo(
    () => tablaMcd.filter((r) => r.coprimo).length,
    [tablaMcd]
  );

  return (
    <div className="min-h-screen p-5 md:p-10 max-w-6xl mx-auto">
      <header className="mb-8 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-semibold mb-3">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 pulse-ring" />
          CRIPTOGRAFÍA RSA · INTERACTIVO
        </div>
        <h1 className="text-4xl md:text-6xl font-black bg-gradient-to-r from-cyan-300 via-sky-300 to-rose-300 bg-clip-text text-transparent">
          RSA Visual Lab
        </h1>
        <p className="text-gray-400 mt-3 max-w-xl mx-auto">
          Aprende RSA paso a paso: elige dos primos, calcula las claves y mira
          cómo cada carácter se transforma.
        </p>
      </header>

      <Stepper currentStep={step} steps={STEPS} />

      {errores.length > 0 && (
        <div className="mb-6 glass border border-red-500/40 rounded-xl p-4 animate-fade-in">
          {errores.map((err, i) => (
            <p key={i} className="text-red-300 text-sm flex items-center gap-2">
              <span>⚠</span> {err}
            </p>
          ))}
        </div>
      )}

      {/* STEP 0 — Primos */}
      <section
        className={`glass border rounded-2xl p-6 mb-6 transition-all ${
          step === 0
            ? 'border-cyan-500/40 shadow-xl shadow-cyan-500/10'
            : 'border-gray-800 opacity-80'
        }`}
      >
        <div className="flex items-center gap-3 mb-5">
          <span className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 font-bold">
            1
          </span>
          <h2 className="text-xl font-bold text-cyan-200">
            Escoge dos números primos
          </h2>
        </div>
        <div className="grid sm:grid-cols-2 gap-4 mb-4">
          <label className="block">
            <span className="text-xs text-gray-400 uppercase tracking-wider">P · primo</span>
            <input
              type="number"
              value={p}
              onChange={(e) => setP(e.target.value)}
              placeholder="Ej. 17"
              className="mt-1 w-full bg-gray-950/60 border border-gray-700 rounded-lg px-4 py-3 text-lg font-mono focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/30 outline-none transition"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400 uppercase tracking-wider">Q · primo</span>
            <input
              type="number"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Ej. 23"
              className="mt-1 w-full bg-gray-950/60 border border-gray-700 rounded-lg px-4 py-3 text-lg font-mono focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/30 outline-none transition"
            />
          </label>
        </div>
        <button
          onClick={handleGenerar}
          disabled={loading || !p || !q}
          className="w-full py-3 rounded-lg font-bold bg-gradient-to-r from-cyan-500 to-sky-500 hover:from-cyan-400 hover:to-sky-400 text-gray-950 disabled:from-gray-700 disabled:to-gray-700 disabled:text-gray-500 disabled:cursor-not-allowed transition-all shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/40"
        >
          {loading ? 'Calculando...' : '→ Calcular n, φ(n) y candidatos de e'}
        </button>

        {n !== null && (
          <div className="mt-5 grid grid-cols-2 gap-3 animate-fade-in">
            <div className="bg-gray-950/70 border border-cyan-500/20 rounded-lg p-3 text-center">
              <p className="text-[10px] uppercase tracking-wider text-gray-500">
                n = p × q
              </p>
              <p className="font-mono text-2xl font-bold text-cyan-300 mt-1">{n}</p>
            </div>
            <div className="bg-gray-950/70 border border-rose-500/20 rounded-lg p-3 text-center">
              <p className="text-[10px] uppercase tracking-wider text-gray-500">
                φ(n) = (p−1)(q−1)
              </p>
              <p className="font-mono text-2xl font-bold text-rose-300 mt-1">{phi}</p>
            </div>
          </div>
        )}
      </section>

      {/* STEP 1 — Elegir e (MCD) */}
      {valoresE.length > 0 && (
        <section
          className={`glass border rounded-2xl p-6 mb-6 transition-all animate-fade-in ${
            step === 1
              ? 'border-cyan-500/40 shadow-xl shadow-cyan-500/10'
              : 'border-gray-800 opacity-80'
          }`}
        >
          <div className="flex items-center gap-3 mb-5">
            <span className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 font-bold">
              2
            </span>
            <h2 className="text-xl font-bold text-cyan-200">
              Escoge e coprimo con φ(n)
            </h2>
            <span className="ml-auto text-xs text-gray-400">
              {coprimosCount} coprimos encontrados
            </span>
          </div>

          <div className="mb-5">
            <p className="text-sm text-gray-400 mb-2">
              Haz click en un número. Los <span className="text-emerald-300">verdes</span> cumplen{' '}
              <span className="font-mono">gcd(e, φ) = 1</span>.
            </p>
            <div className="grid grid-cols-6 sm:grid-cols-10 gap-2 max-h-60 overflow-y-auto custom-scrollbar p-1">
              {tablaMcd.map((fila) => {
                const active = String(fila.e) === String(eSeleccionado);
                return (
                  <button
                    key={fila.e}
                    onClick={() => fila.coprimo && setESeleccionado(String(fila.e))}
                    disabled={!fila.coprimo}
                    title={`gcd(${fila.e}, ${fila.phi}) = ${fila.gcd}`}
                    className={`aspect-square rounded-lg border font-mono font-bold text-sm transition-all ${
                      active
                        ? 'bg-cyan-400 border-cyan-300 text-gray-950 scale-110 shadow-lg shadow-cyan-500/40'
                        : fila.coprimo
                        ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/20 hover:scale-105 cursor-pointer'
                        : 'bg-gray-900/40 border-gray-800 text-gray-600 cursor-not-allowed line-through'
                    }`}
                  >
                    {fila.e}
                  </button>
                );
              })}
            </div>
          </div>

          <button
            onClick={handleSelectE}
            disabled={loading || !eSeleccionado}
            className="w-full py-3 rounded-lg font-bold bg-gradient-to-r from-rose-500 to-pink-500 hover:from-rose-400 hover:to-pink-400 text-gray-950 disabled:from-gray-700 disabled:to-gray-700 disabled:text-gray-500 disabled:cursor-not-allowed transition-all shadow-lg shadow-rose-500/20"
          >
            {eSeleccionado
              ? `→ Calcular d con e = ${eSeleccionado}`
              : 'Elige un valor de e'}
          </button>

          {publicKey && privateKey && (
            <div className="grid md:grid-cols-2 gap-4 mt-6 animate-fade-in">
              <KeyCard
                label="Clave pública"
                subtitle="compartir libremente"
                icon="🔓"
                color="cyan"
                values={{ a: publicKey.n, b: publicKey.e }}
              />
              <KeyCard
                label="Clave privada"
                subtitle="mantener en secreto"
                icon="🔒"
                color="rose"
                values={{ a: privateKey.n, b: privateKey.d }}
              />
            </div>
          )}
        </section>
      )}

      {/* STEP 2 — Cifrar */}
      {publicKey && (
        <section
          className={`glass border rounded-2xl p-6 mb-6 transition-all animate-fade-in ${
            step === 2
              ? 'border-cyan-500/40 shadow-xl shadow-cyan-500/10'
              : 'border-gray-800 opacity-80'
          }`}
        >
          <div className="flex items-center gap-3 mb-5">
            <span className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-300 font-bold">
              3
            </span>
            <h2 className="text-xl font-bold text-cyan-200">Cifra tu mensaje</h2>
          </div>

          <div className="flex flex-col sm:flex-row gap-3 mb-3">
            <input
              type="text"
              value={mensaje}
              onChange={(e) => setMensaje(e.target.value)}
              placeholder="Escribe aquí... (ej. Hola)"
              className="flex-1 bg-gray-950/60 border border-gray-700 rounded-lg px-4 py-3 font-mono focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/30 outline-none"
            />
            <button
              onClick={handleCifrar}
              disabled={loading || !mensaje}
              className="px-6 py-3 rounded-lg font-bold bg-gradient-to-r from-cyan-500 to-sky-500 hover:from-cyan-400 hover:to-sky-400 text-gray-950 disabled:from-gray-700 disabled:to-gray-700 disabled:text-gray-500 disabled:cursor-not-allowed transition-all shadow-lg shadow-cyan-500/20"
            >
              🔐 Cifrar
            </button>
          </div>

          {cipher.length > 0 && (
            <>
              <div className="p-4 bg-gray-950/70 border border-rose-500/30 rounded-lg animate-fade-in">
                <p className="text-xs text-gray-400 mb-1">Resultado cifrado</p>
                <p className="font-mono text-rose-300 break-all text-sm">
                  {cipherText}
                </p>
              </div>
              <CipherFlow
                mensaje={mensaje}
                cipher={cipher}
                e={publicKey.e}
                n={publicKey.n}
                mode="encrypt"
              />
            </>
          )}
        </section>
      )}

      {/* STEP 3 — Descifrar */}
      {cipher.length > 0 && (
        <section
          className={`glass border rounded-2xl p-6 mb-6 transition-all animate-fade-in ${
            step === 3
              ? 'border-rose-500/40 shadow-xl shadow-rose-500/10'
              : 'border-gray-800 opacity-80'
          }`}
        >
          <div className="flex items-center gap-3 mb-5">
            <span className="w-8 h-8 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-300 font-bold">
              4
            </span>
            <h2 className="text-xl font-bold text-rose-200">
              Descifra con la clave privada
            </h2>
          </div>

          <button
            onClick={handleDescifrar}
            disabled={loading}
            className="w-full py-3 rounded-lg font-bold bg-gradient-to-r from-rose-500 to-pink-500 hover:from-rose-400 hover:to-pink-400 text-gray-950 disabled:from-gray-700 disabled:to-gray-700 disabled:cursor-not-allowed transition-all shadow-lg shadow-rose-500/20"
          >
            🔓 Descifrar mensaje
          </button>

          {mensajeDescifrado && (
            <div className="mt-4 p-5 bg-gradient-to-br from-emerald-500/10 to-cyan-500/10 border border-emerald-500/40 rounded-xl animate-fade-in">
              <p className="text-xs uppercase tracking-wider text-emerald-300 mb-1">
                Mensaje recuperado
              </p>
              <p className="font-mono text-2xl font-bold text-emerald-200 break-all">
                “{mensajeDescifrado}”
              </p>
            </div>
          )}

          {mensajeDescifrado && (
            <CipherFlow
              mensaje={mensajeDescifrado}
              cipher={cipher}
              e={privateKey.d}
              n={privateKey.n}
              mode="decrypt"
            />
          )}
        </section>
      )}

      {/* Consola */}
      <section className="mt-8">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-bold text-gray-200">Bitácora de cálculos</h2>
          <div className="flex gap-2">
            <button
              onClick={() => setConsola([])}
              className="text-xs text-gray-400 hover:text-gray-200 px-3 py-1 rounded border border-gray-800 hover:border-gray-600 transition"
            >
              Limpiar
            </button>
            <button
              onClick={resetAll}
              className="text-xs text-rose-400 hover:text-rose-200 px-3 py-1 rounded border border-rose-500/30 hover:border-rose-500/60 transition"
            >
              Reiniciar todo
            </button>
          </div>
        </div>
        <ConsolePanel lines={consola} />
      </section>

      <footer className="text-center mt-16 pb-10 border-t border-gray-800/50 pt-8">
        <div className="flex flex-col items-center gap-2">
          <p className="text-gray-400 text-sm font-medium">
            Autores: <span className="text-cyan-300">Arley Montaña Fiaga</span> & <span className="text-cyan-300">Camilo Velasco Chaves</span>
          </p>
          <div className="flex items-center gap-3 text-[10px] uppercase tracking-[0.2em] text-gray-500 font-bold">
            <span>Asignatura: Seguridad</span>
            <span className="w-1 h-1 rounded-full bg-gray-700" />
            <span>Especialización AES</span>
            <span className="w-1 h-1 rounded-full bg-gray-700" />
            <span>Pontificia Universidad Javeriana</span>
          </div>
          <p className="text-gray-600 text-[10px] mt-4">
            RSA Visual Lab · {new Date().getFullYear()}
          </p>
        </div>
      </footer>
    </div>
  );
}
