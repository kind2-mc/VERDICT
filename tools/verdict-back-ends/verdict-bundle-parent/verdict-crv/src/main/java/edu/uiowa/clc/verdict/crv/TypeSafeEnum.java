/* See LICENSE in project directory */
package edu.uiowa.clc.verdict.crv;

import java.io.Serializable;

public final class TypeSafeEnum {
    public interface MetaDataKey<T extends Serializable> extends Serializable {
        Class<T> getType();

        String getName();
    }

    public static enum StringEnum implements MetaDataKey<String> {
        Software,
        Hybrid,
        ThirdParty,
        HUMAN;

        @Override
        public Class<String> getType() {
            return String.class;
        }

        @Override
        public String getName() {
            return getDeclaringClass().getName() + "." + name();
        }
    }

    //    public static final MetaDataKey<String> SOFTWARE = StringKeys.Software;
    //    public static final MetaDataKey<String> HYBRID= StringKeys.Hybrid;
    //    public static final MetaDataKey<String> THIRDPARTY= StringKeys.ThirdParty;
}
