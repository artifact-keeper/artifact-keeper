import { useState, useCallback } from 'react'
import { Card, Typography, message, Form } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { searchApi, artifactsApi } from '../api'
import { useDocumentTitle } from '../hooks'
import {
  AdvancedSearchForm,
  SearchResults,
  type AdvancedSearchValues,
  type SearchTabType,
  type ViewMode,
  type SortField,
  type SortOrder,
} from '../components/search'
import type { ArtifactSearchHit } from '../types'

const { Title } = Typography

const Search = () => {
  useDocumentTitle('Search')
  const [searchParams, setSearchParams] = useSearchParams()
  const [form] = Form.useForm()

  // Search state
  const [searchValues, setSearchValues] = useState<AdvancedSearchValues | null>(null)
  const [activeTab, setActiveTab] = useState<SearchTabType>('package')

  // View state
  const [viewMode, setViewMode] = useState<ViewMode>('list')
  const [sortField, setSortField] = useState<SortField>('created_at')
  const [sortOrder, setSortOrder] = useState<SortOrder>('descend')

  // Pagination state
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  // Get initial query from URL
  const urlQuery = searchParams.get('q')
  const urlTab = searchParams.get('tab') as SearchTabType | null

  // Search query
  const { data: searchResults, isLoading, isFetching } = useQuery({
    queryKey: ['advanced-search', searchValues, activeTab, page, pageSize, sortField, sortOrder],
    queryFn: async () => {
      if (!searchValues) return null

      // Handle checksum search separately via dedicated endpoint
      if (activeTab === 'checksum') {
        const checksumValue = searchValues.checksum?.value
        if (!checksumValue) return null

        const algorithmMap = {
          md5: 'md5' as const,
          sha1: 'sha1' as const,
          sha256: 'sha256' as const,
          sha512: 'sha256' as const, // fallback: API only supports sha256/sha1/md5
        }
        const algorithm = algorithmMap[searchValues.checksum?.type ?? 'sha256'] ?? 'sha256'

        const artifacts = await searchApi.checksumSearch({
          checksum: checksumValue,
          algorithm,
        })

        // Wrap in paginated response shape for consistent handling
        return {
          items: artifacts,
          pagination: { page: 1, per_page: artifacts.length, total: artifacts.length, total_pages: 1 },
        }
      }

      // Build search request for all other tabs
      const request: Parameters<typeof searchApi.advancedSearch>[0] = {
        page,
        per_page: pageSize,
      }

      switch (activeTab) {
        case 'package':
          if (searchValues.package?.name) request.query = searchValues.package.name
          if (searchValues.package?.version) request.version = searchValues.package.version
          if (searchValues.package?.repository) request.repository_key = searchValues.package.repository
          if (searchValues.package?.format) request.format = searchValues.package.format
          break
        case 'property':
          // Property search: use query param with filter key:value pairs
          if (searchValues.property?.filters?.length) {
            const queryParts = searchValues.property.filters
              .filter((f) => f.key && f.value)
              .map((f) => `${f.key}:${f.value}`)
            if (queryParts.length > 0) {
              request.query = queryParts.join(' ')
            }
          }
          break
        case 'gavc':
          if (searchValues.gavc?.groupId) request.path = searchValues.gavc.groupId
          if (searchValues.gavc?.artifactId) request.name = searchValues.gavc.artifactId
          if (searchValues.gavc?.version) request.version = searchValues.gavc.version
          break
      }

      return searchApi.advancedSearch(request)
    },
    enabled: !!searchValues,
  })

  // Handle search form submit
  const handleSearch = useCallback((values: AdvancedSearchValues, tab: SearchTabType) => {
    setSearchValues(values)
    setActiveTab(tab)
    setPage(1)

    // Update URL with search query
    const params = new URLSearchParams()
    if (values.package?.name) params.set('q', values.package.name)
    params.set('tab', tab)
    setSearchParams(params)
  }, [setSearchParams])

  // Handle result selection
  const handleSelect = useCallback((_result: ArtifactSearchHit) => {
    // Navigate to artifact detail - handled by SearchResults component
  }, [])

  // Handle download
  const handleDownload = useCallback((result: ArtifactSearchHit) => {
    const url = artifactsApi.getDownloadUrl(result.repository_key, result.path)
    window.open(url, '_blank')
    message.success('Download started')
  }, [])

  // Handle pagination change
  const handlePaginationChange = useCallback((newPage: number, newPageSize: number) => {
    setPage(newPage)
    setPageSize(newPageSize)
  }, [])

  // Handle sort change
  const handleSortChange = useCallback((field: SortField, order: SortOrder) => {
    setSortField(field)
    setSortOrder(order)
  }, [])

  // Transform search results to expected format
  // Note: SearchResult and Artifact types are structurally compatible with ArtifactSearchHit
  // for the fields used by the SearchResults component (name, path, repository_key, etc.)
  const results = (searchResults?.items ?? []) as unknown as ArtifactSearchHit[]

  return (
    <div>
      <Title level={2} style={{ marginBottom: 24 }}>Advanced Search</Title>

      <Card style={{ marginBottom: 24 }}>
        <AdvancedSearchForm
          onSearch={handleSearch}
          loading={isLoading || isFetching}
          defaultTab={urlTab || 'package'}
        />
      </Card>

      {searchValues && (
        <Card>
          <SearchResults
            results={results}
            loading={isLoading || isFetching}
            onSelect={handleSelect}
            onDownload={handleDownload}
            viewMode={viewMode}
            onViewModeChange={setViewMode}
            sortField={sortField}
            sortOrder={sortOrder}
            onSortChange={handleSortChange}
            pagination={{
              current: page,
              pageSize,
              total: searchResults?.pagination?.total ?? 0,
              onChange: handlePaginationChange,
            }}
          />
        </Card>
      )}
    </div>
  )
}

export default Search
