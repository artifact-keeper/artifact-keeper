import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Input, Dropdown } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { searchApi } from '../../../api';
import type { SearchResult } from '../../../api/search';
import { QuickSearchResults } from './QuickSearchResults';
import { colors, spacing, borderRadius } from '../../../styles/tokens';

const { Search } = Input;

export interface QuickSearchProps {
  onSearch?: (query: string) => void;
  onAdvancedClick?: () => void;
  placeholder?: string;
  style?: React.CSSProperties;
}

const DEBOUNCE_DELAY = 300;
const MIN_SEARCH_LENGTH = 2;

export const QuickSearch: React.FC<QuickSearchProps> = ({
  onSearch,
  onAdvancedClick,
  placeholder = 'Search artifacts...',
  style,
}) => {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const performSearch = useCallback(async (searchQuery: string) => {
    if (searchQuery.length < MIN_SEARCH_LENGTH) {
      setResults([]);
      setDropdownOpen(false);
      return;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();

    setLoading(true);
    setDropdownOpen(true);

    try {
      const searchResults = await searchApi.quickSearch({
        query: searchQuery,
        limit: 10,
      });
      setResults(searchResults);
    } catch (error) {
      if (error instanceof Error && error.name !== 'AbortError') {
        console.error('Search failed:', error);
        setResults([]);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const debouncedSearch = useCallback((searchQuery: string) => {
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }

    debounceTimerRef.current = setTimeout(() => {
      performSearch(searchQuery);
    }, DEBOUNCE_DELAY);
  }, [performSearch]);

  useEffect(() => {
    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setQuery(value);

    if (value.length < MIN_SEARCH_LENGTH) {
      setResults([]);
      setDropdownOpen(false);
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
      return;
    }

    debouncedSearch(value);
  }, [debouncedSearch]);

  const handleSearch = useCallback((value: string) => {
    if (value.length >= MIN_SEARCH_LENGTH) {
      onSearch?.(value);
      if (onAdvancedClick) {
        onAdvancedClick();
      } else {
        navigate(`/search?q=${encodeURIComponent(value)}`);
      }
      setDropdownOpen(false);
    }
  }, [onSearch, onAdvancedClick, navigate]);

  const handleSelect = useCallback((result: SearchResult) => {
    setDropdownOpen(false);
    setQuery('');

    if (result.type === 'repository') {
      navigate(`/repositories/${result.repository_key}`);
    } else {
      navigate(`/repositories/${result.repository_key}/artifacts/${result.id}`);
    }
  }, [navigate]);

  const handleViewAll = useCallback(() => {
    if (query.length >= MIN_SEARCH_LENGTH) {
      if (onAdvancedClick) {
        onAdvancedClick();
      } else {
        navigate(`/search?q=${encodeURIComponent(query)}`);
      }
    }
    setDropdownOpen(false);
  }, [query, onAdvancedClick, navigate]);

  const handleDropdownOpenChange = useCallback((open: boolean) => {
    if (!open) {
      setDropdownOpen(false);
    } else if (query.length >= MIN_SEARCH_LENGTH && (results.length > 0 || loading)) {
      setDropdownOpen(true);
    }
  }, [query, results.length, loading]);

  const dropdownContent = (
    <div
      style={{
        backgroundColor: colors.bgContainer,
        borderRadius: borderRadius.lg,
        boxShadow: '0 6px 16px 0 rgba(0, 0, 0, 0.08), 0 3px 6px -4px rgba(0, 0, 0, 0.12), 0 9px 28px 8px rgba(0, 0, 0, 0.05)',
        overflow: 'hidden',
      }}
    >
      <QuickSearchResults
        results={results}
        loading={loading}
        onSelect={handleSelect}
        onViewAll={handleViewAll}
      />
    </div>
  );

  return (
    <Dropdown
      popupRender={() => dropdownContent}
      open={dropdownOpen}
      onOpenChange={handleDropdownOpenChange}
      trigger={['click']}
      placement="bottomLeft"
    >
      <Search
        prefix={<SearchOutlined style={{ color: colors.textSecondary }} />}
        placeholder={placeholder}
        value={query}
        onChange={handleInputChange}
        onSearch={handleSearch}
        allowClear
        style={{
          width: 300,
          ...style,
        }}
        styles={{
          input: {
            borderRadius: borderRadius.md,
          },
        }}
      />
    </Dropdown>
  );
};

export default QuickSearch;
