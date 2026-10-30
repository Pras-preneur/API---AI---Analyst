import React, { useState, useRef } from 'react';
import {
  X,
  Upload,
  FileCode,
  AlertCircle,
  Database,
  ArrowRight,
} from 'lucide-react';
import type { ApiSpec } from '../../types/assistant';
import { uploadSpec } from '../../services/api';
import { mapBackendEndpointsToSpec } from '../../services/proposalAdapter';
import { SAMPLE_SPECS } from '../../data/sampleSpecs';

interface SpecUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSpecLoaded: (spec: ApiSpec) => void;
}

export const SpecUploadModal: React.FC<SpecUploadModalProps> = ({
  isOpen,
  onClose,
  onSpecLoaded,
}) => {
  if (!isOpen) return null;

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isParsing, setIsParsing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleProcessFile = async () => {
    if (!selectedFile) return;

    setIsParsing(true);
    setErrorMessage(null);

    try {
      const { endpoints: backendEndpoints, sessionId } = await uploadSpec(
        selectedFile,
        selectedFile.name
      );
      const rawContent = await selectedFile.text();
      const spec = mapBackendEndpointsToSpec(
        backendEndpoints,
        selectedFile.name,
        sessionId,
        rawContent
      );
      onSpecLoaded(spec);
      onClose();
    } catch (err: any) {
      setErrorMessage(err.details || err.message || 'Failed to parse OpenAPI document via backend.');
    } finally {
      setIsParsing(false);
    }
  };

  const handleSelectSample = async (sample: ApiSpec) => {
    setIsParsing(true);
    setErrorMessage(null);

    try {
      const sampleBlob = new Blob([sample.rawContent || ''], {
        type: sample.format === 'json' ? 'application/json' : 'text/yaml',
      });
      const filename = `${sample.title.toLowerCase().replace(/[^a-z0-9]+/g, '_')}.${sample.format}`;
      const { endpoints: backendEndpoints, sessionId } = await uploadSpec(
        sampleBlob,
        filename
      );
      const spec = mapBackendEndpointsToSpec(
        backendEndpoints,
        sample.title,
        sessionId,
        sample.rawContent
      );
      onSpecLoaded(spec);
      onClose();
    } catch (err: any) {
      setErrorMessage(err.details || err.message || 'Failed to load sample specification via backend.');
    } finally {
      setIsParsing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200 text-slate-800">
        
        {/* Header */}
        <div className="h-16 px-6 border-b border-slate-100 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-sky-100 border border-sky-200 flex items-center justify-center text-sky-600 shadow-xs">
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900 font-display">
                Upload API Specification
              </h3>
              <p className="text-xs text-slate-500 font-mono">
                OpenAPI 3.0+ / Swagger 2.0 (JSON or YAML) • Ingested by Backend
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          
          {/* Error Notice */}
          {errorMessage && (
            <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs font-mono text-rose-800 flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <div>
                <div className="font-bold text-rose-900">Backend Ingestion Failure</div>
                <div className="mt-0.5 text-rose-700">{errorMessage}</div>
              </div>
            </div>
          )}

          {/* Drag & Drop Zone */}
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-slate-300 hover:border-sky-400 rounded-2xl p-8 text-center cursor-pointer transition-all bg-slate-50/70 hover:bg-sky-50/40 group"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,.yaml,.yml"
              onChange={handleFileChange}
              className="hidden"
            />
            <div className="w-12 h-12 rounded-xl bg-white group-hover:bg-sky-100 border border-slate-200 group-hover:border-sky-300 flex items-center justify-center mx-auto mb-3 text-slate-400 group-hover:text-sky-600 transition-all shadow-xs">
              <FileCode className="w-6 h-6" />
            </div>
            {selectedFile ? (
              <div className="space-y-1">
                <div className="text-xs font-mono font-bold text-sky-700">
                  {selectedFile.name}
                </div>
                <div className="text-[11px] text-slate-500 font-mono">
                  {(selectedFile.size / 1024).toFixed(1)} KB • Click to change file
                </div>
              </div>
            ) : (
              <div className="space-y-1">
                <div className="text-sm font-semibold text-slate-700">
                  Drop your OpenAPI specification here, or <span className="text-sky-600 font-bold">browse</span>
                </div>
                <p className="text-xs text-slate-400 font-mono">
                  Transmits directly to backend POST /parse-openapi
                </p>
              </div>
            )}
          </div>

          {/* Process Button */}
          {selectedFile && (
            <button
              onClick={handleProcessFile}
              disabled={isParsing}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
            >
              {isParsing ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Ingesting via FastAPI Backend...</span>
                </>
              ) : (
                <>
                  <span>Parse & Ingest Specification</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          )}

          {/* Quick-Load Sample APIs for Evaluators */}
          <div className="pt-3 border-t border-slate-100">
            <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider mb-2 font-semibold">
              Or Load Backend-Verified Evaluator Sample APIs:
            </div>
            <div className="grid grid-cols-1 gap-2">
              {SAMPLE_SPECS.map((sample) => (
                <button
                  key={sample.id}
                  disabled={isParsing}
                  onClick={() => handleSelectSample(sample)}
                  className="w-full text-left p-3 rounded-xl bg-slate-50 hover:bg-slate-100 border border-slate-200 hover:border-sky-300 transition-all flex items-center justify-between group shadow-xs disabled:opacity-50"
                >
                  <div className="flex items-center gap-2.5">
                    <Database className="w-4 h-4 text-sky-600" />
                    <div>
                      <div className="text-xs font-semibold text-slate-800 group-hover:text-sky-700 transition-colors">
                        {sample.title}
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        {sample.endpoints.length} Endpoints • {sample.format.toUpperCase()} • Live Backend Session
                      </div>
                    </div>
                  </div>
                  <span className="text-xs font-mono text-sky-600 flex items-center gap-1 group-hover:translate-x-1 transition-transform font-medium">
                    <span>{isParsing ? 'Ingesting...' : 'Ingest'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </span>
                </button>
              ))}
            </div>
          </div>

        </div>

      </div>
    </div>
  );
};
