package com.dts.entry.profileservice.controller;

import com.dts.entry.profileservice.consts.PaginationConsts;
import com.dts.entry.profileservice.service.ProfileService;
import com.dts.entry.profileservice.viewmodel.request.UpdatedProfileRequest;
import com.dts.entry.profileservice.viewmodel.request.UserProfileCreation;
import com.dts.entry.profileservice.viewmodel.response.BaseResponse;
import com.dts.entry.profileservice.viewmodel.response.Pagination;
import com.dts.entry.profileservice.viewmodel.response.UserProfileResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;

@RestController
@RequestMapping("/profile")
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
@RequiredArgsConstructor
public class ProfileController {

    ProfileService profileService;

    @GetMapping("/test")
    @PreAuthorize("hasRole('USER')")
    public String test() {
        log.info("Test endpoint hit");
        return "Profile service is running";
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<BaseResponse<UserProfileResponse>> getProfile(HttpServletRequest request) throws ParseException {
        UserProfileResponse data = profileService.getProfile(request);
        BaseResponse<UserProfileResponse> response = BaseResponse.<UserProfileResponse>builder()
                .status("success")
                .message("Profile retrieved successfully")
                .data(data)
                .build();
        return ResponseEntity.ok(response);
    }

    @PutMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<BaseResponse<UserProfileResponse>> updateProfile(
            @ModelAttribute UpdatedProfileRequest profileRequest,
            HttpServletRequest httpRequest) throws IOException, ParseException {

        UserProfileResponse data = profileService.updateProfile(profileRequest, httpRequest);

        BaseResponse<UserProfileResponse> response = BaseResponse.<UserProfileResponse>builder()
                .status("success")
                .message("Profile updated successfully")
                .data(data)
                .build();

        return ResponseEntity.ok(response);
    }

    // Get user List Admin
    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BaseResponse<List<UserProfileResponse>>> getUserListAdmin(
            @RequestParam(value = "size", defaultValue = PaginationConsts.DEFAULT_SIZE) int size,
            @RequestParam(value = "page", defaultValue = PaginationConsts.DEFAULT_PAGE) int page) {
        Page<UserProfileResponse> userProfiles = profileService.getAllProfiles(size, page - 1);
        BaseResponse<List<UserProfileResponse>> response = BaseResponse.<List<UserProfileResponse>>builder()
                .status("success")
                .message("User list retrieved successfully")
                .data(userProfiles.getContent())
                .pagination(Pagination.builder()
                        .currentPage(userProfiles.getNumber() +1)
                        .totalPages(userProfiles.getTotalPages())
                        .pageSize(userProfiles.getSize())
                        .totalItems((int) userProfiles.getTotalElements())
                        .hasNextPage(userProfiles.hasNext())
                        .hasPreviousPage(!userProfiles.hasPrevious())
                        .build())
                .build();
        return ResponseEntity.ok(response);
    }
    // Tạo User Admin
    @PostMapping(value = "/admin/users", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BaseResponse<UserProfileResponse>> createUser(@ModelAttribute
                                                                            UserProfileCreation userProfileCreation,
                                                                        HttpServletRequest request) throws IOException, ParseException {
        UserProfileResponse userProfileResponse = profileService.createUser(userProfileCreation, request);
        BaseResponse<UserProfileResponse> response = BaseResponse.<UserProfileResponse>builder()
                .status("success")
                .message("User created successfully")
                .data(userProfileResponse)
                .build();
        return ResponseEntity.ok(response);
    }
    // View Detail User ADmin
    @PostMapping("/admin/users/{profileId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<BaseResponse<UserProfileResponse>> getUserDetailAdmin(
            @PathVariable("profileId") String profileId) throws ParseException {
        UserProfileResponse data = profileService.getProfileAdmin(profileId);
        BaseResponse<UserProfileResponse> response = BaseResponse.<UserProfileResponse>builder()
                .status("success")
                .message("User detail retrieved successfully")
                .data(data)
                .build();
        return ResponseEntity.ok(response);
    }
    // Reset Password Admin

    // Soft Delete user Admin

    // Assign Role Admin

    // Unassign Role Admin


    // Activate User Admin

    // Deactivate User Admin
}
