/*
 * Copyright 2016 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package io.netty5.util;

import io.netty5.util.internal.ObjectUtil;
import io.netty5.util.internal.PlatformDependent;
import io.netty5.util.internal.SystemPropertyUtil;
import io.netty5.util.internal.logging.InternalLogger;
import io.netty5.util.internal.logging.InternalLoggerFactory;

import java.lang.reflect.Constructor;

import static java.util.Objects.requireNonNull;

/**
 * This static factory should be used to load {@link ResourceLeakDetector}s as needed
 */
public abstract class ResourceLeakDetectorFactory {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(ResourceLeakDetectorFactory.class);

    private static volatile ResourceLeakDetectorFactory factoryInstance = new DefaultResourceLeakDetectorFactory();

    /**
     * Get the singleton instance of this factory class.
     *
     * @return the current {@link ResourceLeakDetectorFactory}
     */
    public static ResourceLeakDetectorFactory instance() {
        return factoryInstance;
    }

    /**
     * Set the factory's singleton instance. This has to be called before the static initializer of the
     * {@link ResourceLeakDetector} is called by all the callers of this factory. That is, before initializing a
     * Netty Bootstrap.
     *
     * @param factory the instance that will become the current {@link ResourceLeakDetectorFactory}'s singleton
     */
    public static void setResourceLeakDetectorFactory(ResourceLeakDetectorFactory factory) {
        factoryInstance = requireNonNull(factory, "factory");
    }

    /**
     * Returns a new instance of a {@link ResourceLeakDetector} with the given resource class.
     *
     * @param resource the resource class used to initialize the {@link ResourceLeakDetector}
     * @param <T> the type of the resource class
     * @return a new instance of {@link ResourceLeakDetector}
     */
    public final <T> ResourceLeakDetector<T> newResourceLeakDetector(Class<T> resource) {
        return newResourceLeakDetector(resource, ResourceLeakDetector.SAMPLING_INTERVAL);
    }

    /**
     * Returns a new instance of a {@link ResourceLeakDetector} with the given resource class.
     *
     * @param resource the resource class used to initialize the {@link ResourceLeakDetector}
     * @param samplingInterval the interval on which sampling takes place
     * @param <T> the type of the resource class
     * @return a new instance of {@link ResourceLeakDetector}
     */
    public abstract <T> ResourceLeakDetector<T> newResourceLeakDetector(
            Class<T> resource, int samplingInterval);

    /**
     * Default implementation that loads custom leak detector via system property
     */
    private static final class DefaultResourceLeakDetectorFactory extends ResourceLeakDetectorFactory {
        private final Constructor<?> customClassConstructor;

        DefaultResourceLeakDetectorFactory() {
            String customLeakDetector;
            try {
                customLeakDetector = SystemPropertyUtil.get("io.netty5.customResourceLeakDetector");
            } catch (Throwable cause) {
                logger.error("Could not access System property: io.netty5.customResourceLeakDetector", cause);
                customLeakDetector = null;
            }
            if (customLeakDetector == null) {
                customClassConstructor = null;
            } else {
                customClassConstructor = customClassConstructor(customLeakDetector);
            }
        }

        private static Constructor<?> customClassConstructor(String customLeakDetector) {
            try {
                final Class<?> detectorClass = Class.forName(customLeakDetector, true,
                        PlatformDependent.getSystemClassLoader());

                if (ResourceLeakDetector.class.isAssignableFrom(detectorClass)) {
                    return detectorClass.getConstructor(Class.class, int.class);
                } else {
                    logger.error("Class {} does not inherit from ResourceLeakDetector.", customLeakDetector);
                }
            } catch (Throwable t) {
                logger.error("Could not load custom resource leak detector class provided: {}",
                        customLeakDetector, t);
            }
            return null;
        }

        @Override
        public <T> ResourceLeakDetector<T> newResourceLeakDetector(Class<T> resource, int samplingInterval) {
            ObjectUtil.checkPositive(samplingInterval, "samplingInterval");
            if (customClassConstructor != null) {
                try {
                    @SuppressWarnings("unchecked")
                    ResourceLeakDetector<T> leakDetector =
                            (ResourceLeakDetector<T>) customClassConstructor.newInstance(resource, samplingInterval);
                    logger.debug("Loaded custom ResourceLeakDetector: {}",
                            customClassConstructor.getDeclaringClass().getName());
                    return leakDetector;
                } catch (Throwable t) {
                    logger.error(
                            "Could not load custom resource leak detector provided: {} with the given resource: {}",
                            customClassConstructor.getDeclaringClass().getName(), resource, t);
                }
            }

            ResourceLeakDetector<T> resourceLeakDetector = new ResourceLeakDetector<>(resource, samplingInterval);
            logger.debug("Loaded default ResourceLeakDetector: {}", resourceLeakDetector);
            return resourceLeakDetector;
        }
    }
}