      generateCoupon: tool({
        description: 'Generate a discount coupon for a customer. ONLY use this when the coupon policy conditions are FULLY met! NEVER generate a coupon without a VERIFIED damaged order! This is EXTREMELY IMPORTANT!!!',
        inputSchema: z.object({
          discount: z.number().describe('The discount percentage for the coupon (maximum 10)')
        }),
        execute: async ({ discount }) => {
          const cappedDiscount = Math.max(0, Math.min(Math.trunc(discount), MAX_CHATBOT_COUPON_DISCOUNT))
          const couponCode = security.generateCoupon(cappedDiscount)
          return { couponCode, discount: cappedDiscount }
        }
      })
    }