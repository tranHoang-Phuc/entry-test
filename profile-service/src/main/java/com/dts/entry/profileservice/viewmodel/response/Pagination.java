package com.dts.entry.profileservice.viewmodel.response;

import lombok.Builder;

@Builder
public record Pagination(
        int currentPage,
        int totalPages,
        int pageSize,
        int totalItems,
        boolean hasNextPage,
        boolean hasPreviousPage
) {

}