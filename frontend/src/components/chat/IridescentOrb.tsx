import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Mic, Sparkles, Volume2, MicOff } from 'lucide-react';

export type OrbState = 'idle' | 'listening' | 'processing' | 'responding';

interface IridescentOrbProps {
  state?: OrbState;
  isLoading?: boolean;
  isSpeaking?: boolean;
  onClick?: () => void;
  className?: string;
  size?: number; // default ~220px
}

export const IridescentOrb: React.FC<IridescentOrbProps> = ({
  state,
  isLoading = false,
  isSpeaking = false,
  onClick,
  className = '',
  size = 220,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  // Compute active state
  const activeState: OrbState =
    state || (isLoading ? 'processing' : isSpeaking ? 'listening' : 'idle');

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = size;
    const height = size;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.z = 4.2;

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // Main 3D group for parallax & animation
    const orbGroup = new THREE.Group();
    scene.add(orbGroup);

    // 2. Custom Iridescent Shader Sphere
    const sphereGeo = new THREE.SphereGeometry(1.28, 64, 64);

    const sphereUniforms = {
      uTime: { value: 0 },
      uSpeed: { value: 0.6 },
      uState: { value: 0.0 }, // 0: idle, 1: listening, 2: processing, 3: responding
      uHover: { value: 0.0 },
      uMouse: { value: new THREE.Vector2(0, 0) },
    };

    const vertexShader = `
      varying vec3 vNormal;
      varying vec3 vPosition;
      varying vec2 vUv;
      varying vec3 vViewPosition;
      uniform float uTime;
      uniform float uSpeed;
      uniform float uState;

      void main() {
        vNormal = normalize(normalMatrix * normal);
        vPosition = position;
        vUv = uv;

        // Subtle gentle breathing deformation
        float wave = sin(position.y * 3.0 + uTime * uSpeed * 2.0) * 0.02;
        if (uState == 1.0) { // Listening
          wave = sin(position.y * 6.0 + uTime * 6.0) * 0.05;
        } else if (uState == 2.0) { // Processing
          wave = cos(position.x * 5.0 + uTime * 5.0) * 0.035;
        }

        vec3 newPos = position + normal * wave;
        vec4 mvPosition = modelViewMatrix * vec4(newPos, 1.0);
        vViewPosition = -mvPosition.xyz;
        gl_Position = projectionMatrix * mvPosition;
      }
    `;

    const fragmentShader = `
      varying vec3 vNormal;
      varying vec3 vPosition;
      varying vec2 vUv;
      varying vec3 vViewPosition;
      uniform float uTime;
      uniform float uSpeed;
      uniform float uState;
      uniform float uHover;
      uniform vec2 uMouse;

      void main() {
        vec3 normal = normalize(vNormal);
        vec3 viewDir = normalize(vViewPosition);

        // Slow animated color rotation angles
        float t = uTime * uSpeed * 0.4;
        float nx = normal.x * cos(t) - normal.z * sin(t);
        float nz = normal.x * sin(t) + normal.z * cos(t);
        float ny = normal.y;

        // Palette anchors:
        // Hot Pink: #f43f5e / #ec4899
        // Radiant Magenta: #d946ef / #c026d3
        // Violet/Purple: #8b5cf6 / #6d28d9
        // Luminous Cyan / Turquoise: #06b6d4 / #38bdf8
        // Soft Gold / Peach highlight: #fde047 / #fda4af
        vec3 colPink = vec3(0.96, 0.28, 0.60);
        vec3 colMagenta = vec3(0.85, 0.22, 0.88);
        vec3 colPurple = vec3(0.52, 0.22, 0.92);
        vec3 colCyan = vec3(0.12, 0.76, 0.95);
        vec3 colSoftWhite = vec3(1.0, 0.95, 0.98);

        // Multi-stop gradient blending based on surface normal + time
        float pFactor = smoothstep(-1.0, 1.0, ny + nx * 0.5);
        float cFactor = smoothstep(-0.8, 0.8, -ny + nz * 0.6);
        
        vec3 baseColor = mix(colPurple, colPink, pFactor);
        baseColor = mix(baseColor, colMagenta, sin(t + nx * 2.0) * 0.5 + 0.5);
        baseColor = mix(baseColor, colCyan, cFactor * 0.65);

        // State reactivity
        if (uState == 1.0) { // Listening: more vibrant turquoise & hot pink
          baseColor = mix(baseColor, vec3(1.0, 0.2, 0.65), 0.35);
        } else if (uState == 2.0) { // Processing: energetic violet shift
          baseColor = mix(baseColor, vec3(0.65, 0.25, 1.0), 0.4);
        }

        // Fresnel Edge / Rim Glow (Apple-style iridescence)
        float fresnel = 1.0 - max(dot(viewDir, normal), 0.0);
        fresnel = pow(fresnel, 2.2);
        vec3 rimColor = mix(colCyan, colSoftWhite, fresnel);
        baseColor += rimColor * fresnel * 0.9;

        // Primary Glossy Specular Highlight (Upper Left)
        vec3 lightDir1 = normalize(vec3(-0.8 + uMouse.x * 0.5, 0.9 + uMouse.y * 0.5, 1.2));
        vec3 halfDir1 = normalize(lightDir1 + viewDir);
        float spec1 = pow(max(dot(normal, halfDir1), 0.0), 45.0);
        baseColor += colSoftWhite * spec1 * 1.1;

        // Secondary Soft Rim Specular (Lower Right)
        vec3 lightDir2 = normalize(vec3(0.8, -0.7, 0.6));
        vec3 halfDir2 = normalize(lightDir2 + viewDir);
        float spec2 = pow(max(dot(normal, halfDir2), 0.0), 20.0);
        baseColor += colCyan * spec2 * 0.55;

        // Gentle inner glow
        float innerGlow = smoothstep(0.0, 1.0, dot(viewDir, normal));
        baseColor += colPink * (1.0 - innerGlow) * 0.25;

        gl_FragColor = vec4(baseColor, 0.96);
      }
    `;

    const sphereMat = new THREE.ShaderMaterial({
      vertexShader,
      fragmentShader,
      uniforms: sphereUniforms,
      transparent: true,
    });

    const sphereMesh = new THREE.Mesh(sphereGeo, sphereMat);
    orbGroup.add(sphereMesh);

    // 3. Orbiting Energy Ring
    const ringGeo = new THREE.TorusGeometry(1.68, 0.018, 16, 100);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0xec4899,
      transparent: true,
      opacity: 0.4,
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = Math.PI / 2.5;
    ringMesh.rotation.y = Math.PI / 6;
    orbGroup.add(ringMesh);

    // 4. Orbiting Light Particles
    const particleCount = 24;
    const particleGeo = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    const particleAngles = new Float32Array(particleCount);
    const particleRadii = new Float32Array(particleCount);
    const particleSpeeds = new Float32Array(particleCount);

    for (let i = 0; i < particleCount; i++) {
      particleAngles[i] = (i / particleCount) * Math.PI * 2;
      particleRadii[i] = 1.6 + Math.random() * 0.35;
      particleSpeeds[i] = 0.5 + Math.random() * 0.5;

      const x = Math.cos(particleAngles[i]) * particleRadii[i];
      const y = (Math.random() - 0.5) * 0.4;
      const z = Math.sin(particleAngles[i]) * particleRadii[i];

      particlePositions[i * 3] = x;
      particlePositions[i * 3 + 1] = y;
      particlePositions[i * 3 + 2] = z;
    }

    particleGeo.setAttribute(
      'position',
      new THREE.BufferAttribute(particlePositions, 3)
    );

    const particleMat = new THREE.PointsMaterial({
      color: 0xffd6ea,
      size: 0.045,
      transparent: true,
      opacity: 0.75,
      blending: THREE.AdditiveBlending,
    });

    const particles = new THREE.Points(particleGeo, particleMat);
    orbGroup.add(particles);

    // 5. Mouse Parallax Handler
    let targetRotX = 0;
    let targetRotY = 0;
    let mouseX = 0;
    let mouseY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      mouseX = x * 2;
      mouseY = -y * 2;
      targetRotX = y * 0.6;
      targetRotY = x * 0.8;
      sphereUniforms.uMouse.value.set(x, y);
    };

    window.addEventListener('mousemove', handleMouseMove);

    // 6. Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Update shader uniforms
      sphereUniforms.uTime.value = elapsedTime;

      // State parameter mapping
      if (activeState === 'listening') {
        sphereUniforms.uState.value = 1.0;
        sphereUniforms.uSpeed.value = 1.8;
      } else if (activeState === 'processing') {
        sphereUniforms.uState.value = 2.0;
        sphereUniforms.uSpeed.value = 2.4;
      } else if (activeState === 'responding') {
        sphereUniforms.uState.value = 3.0;
        sphereUniforms.uSpeed.value = 1.4;
      } else {
        sphereUniforms.uState.value = 0.0;
        sphereUniforms.uSpeed.value = 0.6;
      }

      // Smooth floating motion
      const floatOffset = Math.sin(elapsedTime * 1.2) * 0.08;
      sphereMesh.position.y = floatOffset;

      // Smooth mouse parallax
      orbGroup.rotation.x += (targetRotX - orbGroup.rotation.x) * 0.05;
      orbGroup.rotation.y += (targetRotY - orbGroup.rotation.y) * 0.05;

      // Rotate ring & particles
      const ringSpeed = activeState === 'processing' ? 2.5 : 0.8;
      ringMesh.rotation.z += 0.005 * ringSpeed;
      ringMesh.position.y = floatOffset * 0.5;

      // Update particles
      const positions = particleGeo.attributes.position.array as Float32Array;
      for (let i = 0; i < particleCount; i++) {
        particleAngles[i] += 0.008 * particleSpeeds[i] * ringSpeed;
        const r = particleRadii[i];
        positions[i * 3] = Math.cos(particleAngles[i]) * r;
        positions[i * 3 + 2] = Math.sin(particleAngles[i]) * r;
      }
      particleGeo.attributes.position.needsUpdate = true;
      particles.position.y = floatOffset * 0.6;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('mousemove', handleMouseMove);
      renderer.dispose();
      sphereGeo.dispose();
      sphereMat.dispose();
      ringGeo.dispose();
      ringMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [size, activeState]);

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      className={`relative flex flex-col items-center justify-center cursor-pointer select-none group transition-transform duration-500 ${className}`}
      title="API Security Intelligence Orb — Click to activate voice or test vectors"
    >
      {/* Expanding Sound-Wave Rings when Listening */}
      {activeState === 'listening' && (
        <>
          <div className="absolute w-56 h-56 rounded-full border border-pink-400/40 animate-ping pointer-events-none" />
          <div className="absolute w-64 h-64 rounded-full border border-cyan-400/30 animate-pulse pointer-events-none" />
        </>
      )}

      {/* Radiant Background Blur Glow */}
      <div
        className={`absolute rounded-full blur-3xl transition-all duration-700 pointer-events-none ${
          activeState === 'listening'
            ? 'w-64 h-64 bg-gradient-to-tr from-pink-400/50 via-fuchsia-400/40 to-cyan-400/40 opacity-90 scale-110 animate-pulse'
            : activeState === 'processing'
            ? 'w-60 h-60 bg-gradient-to-tr from-purple-500/50 via-pink-400/40 to-cyan-300/40 opacity-80 scale-105 animate-spin-slow'
            : isHovered
            ? 'w-56 h-56 bg-gradient-to-tr from-pink-300/50 via-fuchsia-200/40 to-cyan-200/40 opacity-70 scale-105'
            : 'w-48 h-48 bg-gradient-to-tr from-pink-200/40 via-purple-200/30 to-cyan-100/30 opacity-60'
        }`}
      />

      {/* Three.js Canvas Container */}
      <div
        ref={mountRef}
        style={{ width: size, height: size }}
        className="relative z-10 transition-transform duration-300 ease-out group-hover:scale-105"
      />

      {/* Floating Center Icon Glyph */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20">
        <div className="w-10 h-10 rounded-full bg-white/25 backdrop-blur-md border border-white/50 shadow-inner flex items-center justify-center transition-all group-hover:bg-white/35">
          {activeState === 'listening' ? (
            <Volume2 className="w-4 h-4 text-white drop-shadow-md animate-pulse" />
          ) : activeState === 'processing' ? (
            <Sparkles className="w-4 h-4 text-white drop-shadow-md animate-spin" />
          ) : (
            <Mic className="w-4 h-4 text-white/95 drop-shadow-md" />
          )}
        </div>
      </div>

      {/* Mirrored Floor Reflection */}
      <div
        style={{ width: size * 0.9, height: size * 0.28 }}
        className="relative -mt-3 overflow-hidden pointer-events-none select-none z-0"
      >
        <div
          className="w-full h-full rounded-full transform scale-y-[-1] opacity-35 blur-[4px]"
          style={{
            background:
              'radial-gradient(circle at 50% 20%, rgba(244, 114, 182, 0.85) 0%, rgba(192, 38, 211, 0.6) 40%, rgba(6, 182, 212, 0.4) 75%, transparent 100%)',
            maskImage:
              'linear-gradient(to bottom, rgba(0,0,0,0.85) 0%, rgba(0,0,0,0) 80%)',
            WebkitMaskImage:
              'linear-gradient(to bottom, rgba(0,0,0,0.85) 0%, rgba(0,0,0,0) 80%)',
          }}
        />
      </div>
    </div>
  );
};
