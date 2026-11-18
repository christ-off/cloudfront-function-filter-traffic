// Stand-in for the 'cloudfront' module that only exists in the CloudFront Functions runtime.
// Tests set kvs.exists to control the KeyValueStore answer.
export const kvs = {exists: async () => false};

export default {
    kvs: () => ({exists: (key) => kvs.exists(key)})
};
