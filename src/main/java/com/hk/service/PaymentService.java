package com.hk.service;

import com.hk.model.Order;
import com.hk.response.PaymentResponse;
import com.stripe.exception.StripeException;

public interface PaymentService {

    public PaymentResponse createPaymentLink(Order order) throws StripeException;

}
