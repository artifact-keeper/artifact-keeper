import React, { useCallback, useMemo, useEffect, useRef } from 'react';
import { Tree, Spin, Typography, Tooltip } from 'antd';
import type { TreeProps, TreeDataNode } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';
import { useTreeLoader, TreeNode as HookTreeNode } from '../../../hooks';
import { TreeNode } from '../../../types';
import { treeApi } from '../../../api';
import { colors } from '../../../styles/tokens';
import RepositoryTreeNode from './RepositoryTreeNode';

const { Text } = Typography;

/**
 * Repository item for the tree root level
 */
export interface RepositoryItem {
  id: string;
  key: string;
  name: string;
  format: string;
  repo_type: 'local' | 'remote' | 'virtual';
  is_public: boolean;
  artifact_count?: number;
  storage_used_bytes?: number;
}

/**
 * Props for RepositoryTree component
 */
export interface RepositoryTreeProps {
  /** List of repositories to display at root level */
  repositories: RepositoryItem[];
  /** Callback when a tree node is selected */
  onSelect?: (path: string, node: TreeNode | null) => void;
  /** Currently selected path */
  selectedPath?: string;
  /** Whether the tree is loading initial data */
  loading?: boolean;
  /** Custom class name */
  className?: string;
  /** Custom styles */
  style?: React.CSSProperties;
  /** Whether to show file sizes */
  showSizes?: boolean;
  /** Context menu handler for nodes */
  onContextMenu?: (event: React.MouseEvent, node: TreeNode) => void;
  /** Height for virtual scrolling (enables virtual scroll when set) */
  virtualHeight?: number;
}

/**
 * Convert repository item to tree node format used by the hook
 */
const repositoryToTreeNode = (repo: RepositoryItem): HookTreeNode<TreeNode> => {
  const treeNode: TreeNode = {
    id: repo.id,
    name: repo.name,
    type: 'repository',
    path: repo.key,
    has_children: true,
    metadata: {
      repository: {
        repository_id: repo.id,
        key: repo.key,
        format: repo.format,
        repo_type: repo.repo_type,
        is_public: repo.is_public,
        artifact_count: repo.artifact_count ?? 0,
        storage_used_bytes: repo.storage_used_bytes ?? 0,
      },
    },
  };

  return {
    id: repo.id,
    data: treeNode,
    hasChildren: true,
    parentId: null,
  };
};

/**
 * Convert API tree node to hook tree node format
 */
const apiNodeToHookNode = (node: TreeNode, parentId: string): HookTreeNode<TreeNode> => ({
  id: node.id,
  data: node,
  hasChildren: node.has_children,
  parentId,
});

/**
 * Main tree component that displays repository hierarchy
 *
 * Uses Ant Design Tree component with virtual scrolling for large trees.
 * Integrates with useTreeLoader hook for lazy loading of child nodes.
 *
 * Features:
 * - Shows repository icons based on format (maven, npm, docker, etc.)
 * - Shows repo type indicator (local=green, remote=orange, virtual=purple)
 * - Lazy loads children on expand
 * - Supports virtual scrolling for performance with large trees
 */
export const RepositoryTree: React.FC<RepositoryTreeProps> = ({
  repositories,
  onSelect,
  selectedPath,
  loading = false,
  className,
  style,
  showSizes = true,
  onContextMenu,
  virtualHeight,
}) => {
  /**
   * Load children for a tree node from the API
   */
  const loadChildren = useCallback(
    async (nodeId: string, node: HookTreeNode<TreeNode>): Promise<HookTreeNode<TreeNode>[]> => {
      const nodeData = node.data;

      // Determine repository key and path
      let repositoryKey: string;
      let nodePath: string | undefined;

      if (nodeData.type === 'repository') {
        repositoryKey = nodeData.path;
        nodePath = undefined;
      } else {
        // Extract repository key from the path (first segment)
        const pathParts = nodeData.path.split('/');
        repositoryKey = pathParts[0];
        nodePath = pathParts.slice(1).join('/');
      }

      const children = await treeApi.getChildren({
        repository_key: repositoryKey,
        path: nodePath,
        include_metadata: true,
      });

      return children.map((child) => apiNodeToHookNode(child, nodeId));
    },
    []
  );

  const {
    nodes,
    setNodes,
    expandNode,
    collapseNode,
    isExpanded,
    isLoading,
    getError,
    expandedNodeIds,
  } = useTreeLoader<TreeNode>({
    loadChildren,
  });

  // Keep a ref to current nodes so the effect can read them without re-triggering
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;

  // Update root nodes when repositories change, preserving loaded children
  useEffect(() => {
    const prev = nodesRef.current;
    const prevMap = new Map<string, HookTreeNode<TreeNode>>();
    prev.forEach((n) => prevMap.set(n.id, n));

    const newRoots = repositories.map((repo) => {
      const newNode = repositoryToTreeNode(repo);
      const existing = prevMap.get(newNode.id);
      if (existing?.children) {
        return { ...newNode, children: existing.children };
      }
      return newNode;
    });

    setNodes(newRoots);
  }, [repositories, setNodes]);

  /**
   * Convert hook tree nodes to Ant Design tree data format
   */
  const convertToAntTreeData = useCallback(
    (hookNodes: HookTreeNode<TreeNode>[]): TreeDataNode[] => {
      return hookNodes.map((hookNode) => {
        const nodeData = hookNode.data;
        const nodeLoading = isLoading(hookNode.id);
        const nodeExpanded = isExpanded(hookNode.id);
        const nodeError = getError(hookNode.id);

        // Build title with custom node renderer
        const title = (
          <RepositoryTreeNode
            node={nodeData}
            isExpanded={nodeExpanded}
            showSize={showSizes}
            onContextMenu={onContextMenu}
          />
        );

        // Show loading spinner or error in title if needed
        let displayTitle: React.ReactNode = title;
        if (nodeLoading) {
          displayTitle = (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {title}
              <LoadingOutlined style={{ color: colors.primary, fontSize: 12 }} />
            </div>
          );
        } else if (nodeError) {
          displayTitle = (
            <Tooltip title={nodeError}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {title}
                <Text type="danger" style={{ fontSize: 12 }}>
                  Error
                </Text>
              </div>
            </Tooltip>
          );
        }

        const treeDataNode: TreeDataNode = {
          key: hookNode.id,
          title: displayTitle,
          isLeaf: !hookNode.hasChildren,
          selectable: true,
          children: hookNode.children
            ? convertToAntTreeData(hookNode.children)
            : undefined,
        };

        return treeDataNode;
      });
    },
    [isLoading, isExpanded, getError, showSizes, onContextMenu]
  );

  const treeData = useMemo(
    () => convertToAntTreeData(nodes),
    [nodes, convertToAntTreeData]
  );

  /**
   * Handle tree node expansion
   */
  const handleExpand: TreeProps['onExpand'] = useCallback(
    (expandedKeys: React.Key[], { node, expanded }: { node: { key: React.Key }; expanded: boolean }) => {
      const nodeId = node.key as string;
      if (expanded) {
        expandNode(nodeId);
      } else {
        collapseNode(nodeId);
      }
    },
    [expandNode, collapseNode]
  );

  /**
   * Handle tree node selection
   */
  const handleSelect: TreeProps['onSelect'] = useCallback(
    (selectedKeys: React.Key[], info: unknown) => {
      if (onSelect && selectedKeys.length > 0) {
        const nodeId = selectedKeys[0] as string;

        // Find the node data
        const findNode = (
          hookNodes: HookTreeNode<TreeNode>[]
        ): TreeNode | null => {
          for (const hookNode of hookNodes) {
            if (hookNode.id === nodeId) {
              return hookNode.data;
            }
            if (hookNode.children) {
              const found = findNode(hookNode.children);
              if (found) return found;
            }
          }
          return null;
        };

        const nodeData = findNode(nodes);
        const path = nodeData?.path ?? nodeId;
        onSelect(path, nodeData);
      }
    },
    [onSelect, nodes]
  );

  // Calculate selected keys from selectedPath
  const selectedKeys = useMemo(() => {
    if (!selectedPath) return [];

    // Find node by path
    const findNodeByPath = (
      hookNodes: HookTreeNode<TreeNode>[]
    ): string | null => {
      for (const hookNode of hookNodes) {
        if (hookNode.data.path === selectedPath) {
          return hookNode.id;
        }
        if (hookNode.children) {
          const found = findNodeByPath(hookNode.children);
          if (found) return found;
        }
      }
      return null;
    };

    const nodeId = findNodeByPath(nodes);
    return nodeId ? [nodeId] : [];
  }, [selectedPath, nodes]);

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          padding: 48,
          ...style,
        }}
        className={className}
      >
        <Spin size="large" />
      </div>
    );
  }

  if (repositories.length === 0) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          padding: 48,
          color: colors.textSecondary,
          ...style,
        }}
        className={className}
      >
        <Text type="secondary">No repositories available</Text>
      </div>
    );
  }

  // Tree props with optional virtual scroll
  const treeProps: TreeProps = {
    treeData,
    expandedKeys: expandedNodeIds,
    selectedKeys,
    onExpand: handleExpand,
    onSelect: handleSelect,
    showLine: { showLeafIcon: false },
    showIcon: false,
    blockNode: true,
    style: {
      background: 'transparent',
      ...style,
    },
    className,
  };

  // Enable virtual scrolling if height is specified
  if (virtualHeight) {
    treeProps.height = virtualHeight;
    treeProps.virtual = true;
  }

  return <Tree {...treeProps} />;
};

export default RepositoryTree;
