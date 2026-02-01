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

/// Pagination metadata for list responses.
///
/// Used consistently across all paginated API endpoints to provide
/// standard pagination information to clients.
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Default, Deserialize)]
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
