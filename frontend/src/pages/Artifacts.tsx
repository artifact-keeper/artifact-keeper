import { useState, useCallback, useRef } from 'react'
import { Layout, Spin, message } from 'antd'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { repositoriesApi, artifactsApi, treeApi } from '../api'
import type { Artifact, Repository, TreeNode } from '../types'
import { useDocumentTitle } from '../hooks'
import { useConfirmDialog } from '../components/common'
import {
  RepositoryTree,
  RepositoryItem,
  ArtifactList,
  ArtifactDetail,
} from '../components/repository'
import { colors } from '../styles/tokens'

const { Sider, Content } = Layout

const Artifacts = () => {
  useDocumentTitle('Artifacts')
  const queryClient = useQueryClient()
  const { showConfirm } = useConfirmDialog()

  // State for selection
  const [selectedPath, setSelectedPath] = useState<string | undefined>()
  const [selectedNode, setSelectedNode] = useState<TreeNode | null>(null)
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null)

  // State for pagination
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  // Fetch repositories for the tree
  const { data: reposData, isLoading: reposLoading } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => repositoriesApi.list({ per_page: 100 }),
  })

  // Transform repositories for the tree component
  const repositories: RepositoryItem[] = (reposData?.items ?? []).map((repo: Repository) => ({
    id: repo.id,
    key: repo.key,
    name: repo.name,
    format: repo.format,
    repo_type: repo.repo_type,
    is_public: repo.is_public,
    storage_used_bytes: repo.storage_used_bytes,
  }))

  // Determine if we're viewing a folder or repository
  const getCurrentRepoKey = (): string | undefined => {
    if (!selectedPath) return undefined
    // Extract repository key from path (first segment)
    return selectedPath.split('/')[0]
  }

  const getCurrentFolderPath = (): string | undefined => {
    if (!selectedPath) return undefined
    const parts = selectedPath.split('/')
    if (parts.length <= 1) return undefined
    return parts.slice(1).join('/')
  }

  // Fetch artifacts for selected folder
  const repoKey = getCurrentRepoKey()
  const folderPath = getCurrentFolderPath()

  const { data: artifactsData, isLoading: artifactsLoading } = useQuery({
    queryKey: ['artifacts', repoKey, folderPath, page, pageSize],
    queryFn: () =>
      artifactsApi.list(repoKey!, {
        page,
        per_page: pageSize,
        path: folderPath,
      }),
    enabled: !!repoKey,
  })

  // Fetch single artifact for detail view
  const { data: artifactDetail } = useQuery({
    queryKey: ['artifact', selectedArtifact?.id],
    queryFn: () =>
      selectedArtifact
        ? artifactsApi.get(selectedArtifact.repository_key, selectedArtifact.path)
        : null,
    enabled: !!selectedArtifact,
  })

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: ({ repoKey, path }: { repoKey: string; path: string }) =>
      artifactsApi.delete(repoKey, path),
    onSuccess: () => {
      message.success('Artifact deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['artifacts'] })
      setSelectedArtifact(null)
    },
    onError: () => {
      message.error('Failed to delete artifact')
    },
  })

  // Handle tree node selection
  const handleTreeSelect = useCallback((path: string, node: TreeNode | null) => {
    setSelectedPath(path)
    setSelectedNode(node)
    setSelectedArtifact(null)
    setPage(1)
  }, [])

  // Handle artifact selection from list
  const handleArtifactSelect = useCallback((artifact: Artifact) => {
    setSelectedArtifact(artifact)
  }, [])

  // Handle artifact download
  const handleDownload = useCallback((artifact: Artifact) => {
    const url = artifactsApi.getDownloadUrl(artifact.repository_key, artifact.path)
    window.open(url, '_blank')
  }, [])

  // Handle artifact delete with confirmation
  const handleDelete = useCallback(
    async (artifact: Artifact) => {
      const confirmed = await showConfirm({
        title: 'Delete Artifact',
        content: `Are you sure you want to delete "${artifact.name}"? This action cannot be undone.`,
        type: 'danger',
        confirmText: 'Delete',
        cancelText: 'Cancel',
      })

      if (confirmed) {
        deleteMutation.mutate({
          repoKey: artifact.repository_key,
          path: artifact.path,
        })
      }
    },
    [showConfirm, deleteMutation]
  )

  // Handle copy path action
  const handleCopyPath = useCallback(async (artifact: Artifact) => {
    const fullPath = `${artifact.repository_key}/${artifact.path}`
    try {
      await navigator.clipboard.writeText(fullPath)
      message.success('Path copied to clipboard')
    } catch {
      message.error('Failed to copy path')
    }
  }, [])

  // Handle pagination
  const handlePaginationChange = useCallback((newPage: number, newPageSize: number) => {
    setPage(newPage)
    setPageSize(newPageSize)
  }, [])

  // Resizable left panel
  const [siderWidth, setSiderWidth] = useState(320)
  const isResizing = useRef(false)

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    isResizing.current = true
    const startX = e.clientX
    const startWidth = siderWidth

    const onMouseMove = (moveEvent: MouseEvent) => {
      if (!isResizing.current) return
      const newWidth = Math.max(200, Math.min(600, startWidth + (moveEvent.clientX - startX)))
      setSiderWidth(newWidth)
    }

    const onMouseUp = () => {
      isResizing.current = false
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [siderWidth])

  return (
    <Layout style={{ height: 'calc(100vh - 112px)', background: colors.bgLayout }}>
      {/* Left Panel: Repository Tree */}
      <div
        style={{
          width: siderWidth,
          minWidth: 200,
          maxWidth: 600,
          background: colors.bgContainer,
          overflow: 'auto',
          flexShrink: 0,
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
        }}
      >
        <div style={{ padding: '16px 8px', flex: 1, overflow: 'auto' }}>
          <RepositoryTree
            repositories={repositories}
            loading={reposLoading}
            selectedPath={selectedPath}
            onSelect={handleTreeSelect}
            showSizes
          />
        </div>
      </div>

      {/* Resize handle */}
      <div
        onMouseDown={handleMouseDown}
        style={{
          width: 4,
          cursor: 'col-resize',
          background: colors.border,
          flexShrink: 0,
          transition: 'background 0.15s',
        }}
        onMouseEnter={(e) => { (e.target as HTMLElement).style.background = colors.primary || '#1677ff' }}
        onMouseLeave={(e) => { if (!isResizing.current) (e.target as HTMLElement).style.background = colors.border }}
      />

      {/* Middle Panel: Artifact List */}
      <Content
        style={{
          background: colors.bgContainer,
          borderRight: selectedArtifact ? `1px solid ${colors.border}` : undefined,
          overflow: 'auto',
          minWidth: 400,
        }}
      >
        <div style={{ padding: 16 }}>
          {!selectedPath ? (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                height: 300,
                color: colors.textSecondary,
              }}
            >
              <p>Select a repository or folder from the tree to browse artifacts</p>
            </div>
          ) : artifactsLoading ? (
            <div
              style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: 200,
              }}
            >
              <Spin size="large" />
            </div>
          ) : (
            <ArtifactList
              artifacts={artifactsData?.items ?? []}
              loading={artifactsLoading}
              onSelect={handleArtifactSelect}
              onDownload={handleDownload}
              onDelete={handleDelete}
              pagination={{
                current: page,
                pageSize,
                total: artifactsData?.pagination?.total ?? 0,
                onChange: handlePaginationChange,
              }}
            />
          )}
        </div>
      </Content>

      {/* Right Panel: Artifact Detail */}
      {selectedArtifact && (
        <Sider
          width={400}
          style={{
            background: colors.bgContainer,
            overflow: 'auto',
          }}
        >
          <ArtifactDetail
            artifact={artifactDetail ?? selectedArtifact}
            onDownload={handleDownload}
            onDelete={handleDelete}
            canDelete
          />
        </Sider>
      )}
    </Layout>
  )
}

export default Artifacts
