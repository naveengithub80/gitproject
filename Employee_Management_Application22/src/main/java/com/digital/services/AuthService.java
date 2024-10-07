package com.digital.services;

import com.digital.dto.SignupRequest;
import com.digital.entities.Customer;

public interface AuthService {
    Customer createCustomer(SignupRequest signupRequest);
}
