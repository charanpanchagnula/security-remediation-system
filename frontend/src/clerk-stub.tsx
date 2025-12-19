"use client";
import React from 'react';

export const ClerkProvider = ({ children }: { children: React.ReactNode }) => <>{children}</>;
export const useUser = () => ({ isLoaded: true, isSignedIn: false, user: null });
export const UserButton = () => <div />;
export const SignIn = () => <div />;
export const SignUp = () => <div />;
export const SignedIn = ({ children }: { children: React.ReactNode }) => null;
export const SignedOut = ({ children }: { children: React.ReactNode }) => <>{children}</>;
export const clerkMiddleware = () => (req: any) => { };
export const createRouteMatcher = () => () => false;
