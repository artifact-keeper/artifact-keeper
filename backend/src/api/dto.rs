//! Shared Data Transfer Objects (DTOs) for API handlers.
//!
//! This module provides common structs used across multiple API endpoints
//! to ensure consistency in request/response formats.
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::api::dto::{Pagination, PaginationQuery};
//!
//! // In a list handler:
//! let pagination = Pagination {
//!     page: query.page.unwrap_or(1),
//!     per_page: query.per_page.unwrap_or(20),
//!     total,
//!     total_pages: ((total as f64) / (per_page as f64)).ceil() as u32,
//! };
//! ```

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Pagination metadata for list responses.
///
/// Used consistently across all paginated API endpoints to provide
/// standard pagination information to clients.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Pagination {
    /// Current page number (1-indexed)
    pub page: u32,
    /// Number of items per page
    pub per_page: u32,
    /// Total number of items across all pages
    pub total: i64,
    /// Total number of pages
    pub total_pages: u32,
}

impl Pagination {
    /// Create pagination from query parameters and total count.
    ///
    /// # Arguments
    ///
    /// * `query` - The pagination query parameters from the request
    /// * `total` - The total number of items
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let pagination = Pagination::from_query_and_total(&query.pagination, total_count);
    /// ```
    pub fn from_query_and_total(query: &PaginationQuery, total: i64) -> Self {
        let page = query.page();
        let per_page = query.per_page();
        let total_pages = if total == 0 {
            0
        } else {
            ((total as f64) / (per_page as f64)).ceil() as u32
        };

        Self {
            page,
            per_page,
            total,
            total_pages,
        }
    }
}

/// Query parameters for paginated list requests.
///
/// Provides optional page and per_page parameters with sensible defaults.
/// Can be used with `#[serde(flatten)]` in handler-specific query structs.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct PaginationQuery {
    /// Requested page number (default: 1)
    pub page: Option<u32>,
    /// Requested items per page (default: 20)
    pub per_page: Option<u32>,
}

impl PaginationQuery {
    /// Get the page number, defaulting to 1 if not specified.
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1)
    }

    /// Get the per_page value, defaulting to 20 if not specified.
    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(20)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PaginationQuery
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_query_defaults() {
        let query = PaginationQuery::default();
        assert_eq!(query.page(), 1);
        assert_eq!(query.per_page(), 20);
    }

    #[test]
    fn test_pagination_query_with_page() {
        let query = PaginationQuery {
            page: Some(5),
            per_page: None,
        };
        assert_eq!(query.page(), 5);
        assert_eq!(query.per_page(), 20);
    }

    #[test]
    fn test_pagination_query_with_per_page() {
        let query = PaginationQuery {
            page: None,
            per_page: Some(50),
        };
        assert_eq!(query.page(), 1);
        assert_eq!(query.per_page(), 50);
    }

    #[test]
    fn test_pagination_query_both_specified() {
        let query = PaginationQuery {
            page: Some(3),
            per_page: Some(10),
        };
        assert_eq!(query.page(), 3);
        assert_eq!(query.per_page(), 10);
    }

    // -----------------------------------------------------------------------
    // Pagination::from_query_and_total
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_from_query_basic() {
        let query = PaginationQuery {
            page: Some(1),
            per_page: Some(10),
        };
        let p = Pagination::from_query_and_total(&query, 25);
        assert_eq!(p.page, 1);
        assert_eq!(p.per_page, 10);
        assert_eq!(p.total, 25);
        assert_eq!(p.total_pages, 3); // ceil(25/10) = 3
    }

    #[test]
    fn test_pagination_from_query_exact_division() {
        let query = PaginationQuery {
            page: Some(1),
            per_page: Some(10),
        };
        let p = Pagination::from_query_and_total(&query, 30);
        assert_eq!(p.total_pages, 3); // 30/10 = 3 exactly
    }

    #[test]
    fn test_pagination_from_query_zero_total() {
        let query = PaginationQuery {
            page: Some(1),
            per_page: Some(20),
        };
        let p = Pagination::from_query_and_total(&query, 0);
        assert_eq!(p.total, 0);
        assert_eq!(p.total_pages, 0);
    }

    #[test]
    fn test_pagination_from_query_defaults() {
        let query = PaginationQuery::default();
        let p = Pagination::from_query_and_total(&query, 100);
        assert_eq!(p.page, 1);
        assert_eq!(p.per_page, 20);
        assert_eq!(p.total, 100);
        assert_eq!(p.total_pages, 5); // 100/20 = 5
    }

    #[test]
    fn test_pagination_from_query_single_item() {
        let query = PaginationQuery {
            page: Some(1),
            per_page: Some(10),
        };
        let p = Pagination::from_query_and_total(&query, 1);
        assert_eq!(p.total, 1);
        assert_eq!(p.total_pages, 1);
    }

    #[test]
    fn test_pagination_from_query_per_page_one() {
        let query = PaginationQuery {
            page: Some(1),
            per_page: Some(1),
        };
        let p = Pagination::from_query_and_total(&query, 5);
        assert_eq!(p.total_pages, 5);
    }

    #[test]
    fn test_pagination_from_query_large_per_page() {
        let query = PaginationQuery {
            page: Some(1),
            per_page: Some(1000),
        };
        let p = Pagination::from_query_and_total(&query, 5);
        assert_eq!(p.total_pages, 1); // all items fit on one page
    }

    // -----------------------------------------------------------------------
    // Pagination serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_serialize() {
        let p = Pagination {
            page: 2,
            per_page: 10,
            total: 45,
            total_pages: 5,
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["page"], 2);
        assert_eq!(json["per_page"], 10);
        assert_eq!(json["total"], 45);
        assert_eq!(json["total_pages"], 5);
    }

    // -----------------------------------------------------------------------
    // PaginationQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_query_deserialize_full() {
        let json = r#"{"page": 3, "per_page": 15}"#;
        let query: PaginationQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page(), 3);
        assert_eq!(query.per_page(), 15);
    }

    #[test]
    fn test_pagination_query_deserialize_partial() {
        let json = r#"{"page": 2}"#;
        let query: PaginationQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page(), 2);
        assert_eq!(query.per_page(), 20); // default
    }

    #[test]
    fn test_pagination_query_deserialize_empty() {
        let json = r#"{}"#;
        let query: PaginationQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.page(), 1); // default
        assert_eq!(query.per_page(), 20); // default
    }
}
