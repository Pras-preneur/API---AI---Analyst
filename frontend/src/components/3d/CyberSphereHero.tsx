import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

export const CyberSphereHero: React.FC = () => {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    let width = container.clientWidth || window.innerWidth;
    let height = container.clientHeight || 650;

    // Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.z = 18;

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // Group for mouse parallax
    const mainGroup = new THREE.Group();
    scene.add(mainGroup);

    // 1. Inner glowing cyber core
    const coreGeo = new THREE.SphereGeometry(3.6, 32, 32);
    const coreMat = new THREE.MeshBasicMaterial({
      color: 0x061838,
      transparent: true,
      opacity: 0.85,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    mainGroup.add(coreMesh);

    // 2. Geodesic wireframe shield
    const wireframeGeo = new THREE.IcosahedronGeometry(4.2, 2);
    const wireframeMat = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      wireframe: true,
      transparent: true,
      opacity: 0.35,
    });
    const wireframeMesh = new THREE.Mesh(wireframeGeo, wireframeMat);
    mainGroup.add(wireframeMesh);

    // Outer shield layer
    const outerGeo = new THREE.IcosahedronGeometry(4.7, 1);
    const outerMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      wireframe: true,
      transparent: true,
      opacity: 0.18,
    });
    const outerMesh = new THREE.Mesh(outerGeo, outerMat);
    mainGroup.add(outerMesh);

    // 3. Concentric Orbital Rings
    const ringGeo1 = new THREE.RingGeometry(5.4, 5.48, 64);
    const ringMat1 = new THREE.MeshBasicMaterial({
      color: 0x00f0ff,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.45,
    });
    const ring1 = new THREE.Mesh(ringGeo1, ringMat1);
    ring1.rotation.x = Math.PI / 2.3;
    ring1.rotation.y = Math.PI / 8;
    mainGroup.add(ring1);

    const ringGeo2 = new THREE.RingGeometry(6.2, 6.26, 64);
    const ringMat2 = new THREE.MeshBasicMaterial({
      color: 0x818cf8,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.35,
    });
    const ring2 = new THREE.Mesh(ringGeo2, ringMat2);
    ring2.rotation.x = Math.PI / 1.7;
    ring2.rotation.z = Math.PI / 4;
    mainGroup.add(ring2);

    // 4. Orbiting data packets on ring 1
    const packetCount = 8;
    const packetGeo = new THREE.SphereGeometry(0.12, 12, 12);
    const packetMat = new THREE.MeshBasicMaterial({ color: 0x00ffff });
    const packets: THREE.Mesh[] = [];

    for (let i = 0; i < packetCount; i++) {
      const p = new THREE.Mesh(packetGeo, packetMat);
      mainGroup.add(p);
      packets.push(p);
    }

    // 5. Orbiting API endpoint node satellites
    const endpointNodes: { mesh: THREE.Mesh; angle: number; radius: number; speed: number; y: number }[] = [];
    const nodeColors = [0x00f0ff, 0x38bdf8, 0xf43f5e, 0x10b981];
    
    for (let i = 0; i < 4; i++) {
      const nodeGeo = new THREE.SphereGeometry(0.25, 16, 16);
      const nodeMat = new THREE.MeshBasicMaterial({
        color: nodeColors[i],
        wireframe: false,
      });
      const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
      
      // Halo around node
      const haloGeo = new THREE.RingGeometry(0.35, 0.42, 24);
      const haloMat = new THREE.MeshBasicMaterial({
        color: nodeColors[i],
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.7,
      });
      const halo = new THREE.Mesh(haloGeo, haloMat);
      nodeMesh.add(halo);

      mainGroup.add(nodeMesh);
      endpointNodes.push({
        mesh: nodeMesh,
        angle: (i * Math.PI) / 2,
        radius: 5.6 + (i % 2) * 1.2,
        speed: 0.008 + i * 0.003,
        y: (i - 1.5) * 1.2,
      });
    }

    // 6. Cyber Particle Cloud
    const particleCount = 280;
    const particleGeometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const particleColors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount * 3; i += 3) {
      const radius = 6 + Math.random() * 8;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(Math.random() * 2 - 1);

      positions[i] = radius * Math.sin(phi) * Math.cos(theta);
      positions[i + 1] = radius * Math.sin(phi) * Math.sin(theta);
      positions[i + 2] = radius * Math.cos(phi);

      // Cyan / Blue / Violet tints
      const choice = Math.random();
      if (choice < 0.6) {
        particleColors[i] = 0.0;
        particleColors[i + 1] = 0.94;
        particleColors[i + 2] = 1.0;
      } else if (choice < 0.85) {
        particleColors[i] = 0.22;
        particleColors[i + 1] = 0.74;
        particleColors[i + 2] = 0.97;
      } else {
        particleColors[i] = 0.5;
        particleColors[i + 1] = 0.55;
        particleColors[i + 2] = 0.97;
      }
    }

    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    particleGeometry.setAttribute('color', new THREE.BufferAttribute(particleColors, 3));

    const particleMaterial = new THREE.PointsMaterial({
      size: 0.09,
      vertexColors: true,
      transparent: true,
      opacity: 0.75,
      blending: THREE.AdditiveBlending,
    });

    const particles = new THREE.Points(particleGeometry, particleMaterial);
    mainGroup.add(particles);

    // Ambient and Directional Lights
    const ambientLight = new THREE.AmbientLight(0x0a192f, 2.5);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0x00f0ff, 4, 30);
    pointLight.position.set(0, 0, 0);
    scene.add(pointLight);

    // Mouse Interaction
    let mouseX = 0;
    let mouseY = 0;
    let targetX = 0;
    let targetY = 0;

    const handleMouseMove = (event: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = event.clientX - rect.left - rect.width / 2;
      const y = event.clientY - rect.top - rect.height / 2;
      targetX = (x / rect.width) * 0.6;
      targetY = (y / rect.height) * 0.6;
    };

    window.addEventListener('mousemove', handleMouseMove);

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      width = container.clientWidth;
      height = container.clientHeight;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    };

    const resizeObserver = new ResizeObserver(handleResize);
    resizeObserver.observe(container);

    // Animation Loop
    let animationFrameId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Smooth mouse follow
      mouseX += (targetX - mouseX) * 0.05;
      mouseY += (targetY - mouseY) * 0.05;

      mainGroup.rotation.y = elapsedTime * 0.12 + mouseX * 0.8;
      mainGroup.rotation.x = Math.sin(elapsedTime * 0.1) * 0.1 - mouseY * 0.8;

      // Rotate individual components
      wireframeMesh.rotation.y = -elapsedTime * 0.2;
      wireframeMesh.rotation.x = elapsedTime * 0.1;

      outerMesh.rotation.y = elapsedTime * 0.15;
      outerMesh.rotation.z = -elapsedTime * 0.08;

      ring1.rotation.z = elapsedTime * 0.25;
      ring2.rotation.z = -elapsedTime * 0.2;

      // Packets on ring 1
      packets.forEach((p, idx) => {
        const angle = (idx / packetCount) * Math.PI * 2 + elapsedTime * 0.8;
        const r = 5.44;
        // Transform along ring plane
        const localX = Math.cos(angle) * r;
        const localY = Math.sin(angle) * r;
        
        p.position.set(
          localX * Math.cos(Math.PI / 8) - localY * Math.sin(Math.PI / 8),
          localY * Math.cos(Math.PI / 2.3),
          localX * Math.sin(Math.PI / 8) + localY * Math.sin(Math.PI / 2.3)
        );
      });

      // Endpoint satellite nodes
      endpointNodes.forEach((node) => {
        node.angle += node.speed;
        node.mesh.position.x = Math.cos(node.angle) * node.radius;
        node.mesh.position.z = Math.sin(node.angle) * node.radius;
        node.mesh.position.y = node.y + Math.sin(elapsedTime * 2 + node.angle) * 0.4;
      });

      // Core pulse
      const scale = 1 + Math.sin(elapsedTime * 1.8) * 0.035;
      coreMesh.scale.set(scale, scale, scale);

      // Slow particle rotation
      particles.rotation.y = -elapsedTime * 0.04;

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      resizeObserver.disconnect();
      cancelAnimationFrame(animationFrameId);
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
      wireframeGeo.dispose();
      coreGeo.dispose();
      outerGeo.dispose();
      ringGeo1.dispose();
      ringGeo2.dispose();
      particleGeometry.dispose();
    };
  }, []);

  return (
    <div className="relative w-full h-[520px] md:h-[640px] flex items-center justify-center pointer-events-none select-none">
      {/* 3D Canvas Mount */}
      <div ref={mountRef} className="absolute inset-0 w-full h-full pointer-events-auto" />

      {/* Radiant Background Aura */}
      <div className="absolute w-[360px] md:w-[500px] h-[360px] md:h-[500px] rounded-full bg-cyan-500/10 blur-[90px] -z-10 pointer-events-none" />
      <div className="absolute w-[280px] md:w-[380px] h-[280px] md:h-[380px] rounded-full bg-blue-600/15 blur-[110px] -z-10 pointer-events-none" />

      {/* Floating Hologram Data Badges around the 3D Sphere */}
      <div className="absolute top-12 left-4 md:left-12 max-w-[220px] glass-pill px-4 py-2.5 rounded-xl border border-cyan-500/25 shadow-cyber-glow animate-float hidden sm:block">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span className="text-[11px] font-mono tracking-wider text-cyan-300 font-semibold uppercase">API Shield Core</span>
        </div>
        <p className="text-xs text-slate-300 mt-1 font-medium">Telemetry: 24,800+ packets/sec</p>
      </div>

      <div className="absolute bottom-16 right-4 md:right-12 max-w-[240px] glass-pill px-4 py-3 rounded-xl border border-indigo-500/25 shadow-glass animate-float-reverse hidden sm:block">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono tracking-widest text-indigo-300 uppercase">ML Triage Engine</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-mono font-bold">P1 Active</span>
        </div>
        <p className="text-xs text-slate-200 mt-1.5 font-medium">BOLA & Auth Bypass Radar</p>
        <div className="w-full bg-slate-800/80 rounded-full h-1.5 mt-2 overflow-hidden">
          <div className="bg-gradient-to-r from-cyan-400 to-indigo-500 h-full w-[88%]" />
        </div>
      </div>

      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 glass-pill px-4 py-1.5 rounded-full border border-cyan-400/20 text-[11px] font-mono text-cyan-300 flex items-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        <span>NVIDIA NEMOTRON-70B • ZERO VERDICT OVERWRITE</span>
      </div>
    </div>
  );
};
