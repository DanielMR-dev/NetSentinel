import React, { useEffect, useCallback, useRef, useMemo, memo } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useScanStore } from '../../stores/scanStore';
import {
  useTopologyStore,
  useTopologyViewMode,
} from '../../stores/topologyStore';
import { HostNode } from './HostNode';
import { ClusterNode } from './ClusterNode';
import { TopologyControls } from './TopologyControls';

const nodeTypes = {
  hostNode: HostNode,
  clusterNode: ClusterNode,
};

/** Debounce helper for batching device updates */
function useDebouncedEffect(
  effect: () => void,
  deps: React.DependencyList,
  delay: number
) {
  const callbackRef = useRef(effect);

  useEffect(() => {
    callbackRef.current = effect;
  });

  useEffect(() => {
    const timer = setTimeout(() => {
      callbackRef.current();
    }, delay);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

const TopologyInner: React.FC = memo(() => {
  const devices = useScanStore((s) => s.devices);
  const viewMode = useTopologyViewMode();
  const updateNodesFromDevices = useTopologyStore((s) => s.updateNodesFromDevices);
  const storeNodes = useTopologyStore((s) => s.nodes);
  const storeEdges = useTopologyStore((s) => s.edges);

  const [nodes, setNodes, onNodesChange] = useNodesState(storeNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(storeEdges);
  const { fitView } = useReactFlow();

  // Sync store nodes/edges to local React Flow state
  useEffect(() => {
    setNodes(storeNodes);
  }, [storeNodes, setNodes]);

  useEffect(() => {
    setEdges(storeEdges);
  }, [storeEdges, setEdges]);

  // Debounced update from devices to topology store (100ms batch)
  useDebouncedEffect(
    () => {
      updateNodesFromDevices(devices);
    },
    [devices, updateNodesFromDevices],
    100
  );

  // Re-layout when view mode changes
  useEffect(() => {
    updateNodesFromDevices(devices);
  }, [viewMode, updateNodesFromDevices, devices]);

  const handleFitView = useCallback(() => {
    fitView({ padding: 0.2, duration: 300 });
  }, [fitView]);

  const memoNodeTypes = useMemo(() => nodeTypes, []);

  if (devices.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-500">
        <div className="text-center">
          <svg
            className="w-12 h-12 mx-auto mb-3 text-gray-400 dark:text-gray-600"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <p className="text-sm">Start a scan to see your network topology</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <TopologyControls onFitView={handleFitView} />

      <div className="h-[500px] w-full border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden bg-gray-50 dark:bg-gray-900">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={memoNodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.1}
          maxZoom={3}
          proOptions={{ hideAttribution: true }}
          aria-label={`Network topology showing ${devices.length} devices`}
        >
          <Controls showInteractive={false} />
          <MiniMap
            nodeStrokeWidth={3}
            zoomable
            pannable
            className="!bg-gray-100 dark:!bg-gray-800 !border-gray-200 dark:!border-gray-700"
          />
          <Background
            variant={BackgroundVariant.Dots}
            gap={20}
            size={1}
            color="#94a3b8"
          />
        </ReactFlow>
      </div>
    </div>
  );
});

TopologyInner.displayName = 'TopologyInner';

export const TopologyView: React.FC = () => {
  return (
    <ReactFlowProvider>
      <TopologyInner />
    </ReactFlowProvider>
  );
};
